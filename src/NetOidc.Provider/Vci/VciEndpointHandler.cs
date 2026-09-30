using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Http;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Vci;

/// <summary>
/// Handles the OID4VCI endpoints: credential, nonce, deferred credential, notification and
/// credential offer.
/// </summary>
internal sealed class VciEndpointHandler
{
    private const string ProofTyp = "openid4vci-proof+jwt";

    /// <summary>Maximum age / clock skew accepted for a proof's <c>iat</c>.</summary>
    private static readonly TimeSpan ProofMaxAge = TimeSpan.FromMinutes(5);

    private readonly IOptions<ProviderOptions> _options;
    private readonly VciService _vciService;
    private readonly AccessTokenService _accessTokens;
    private readonly RequestThrottle _throttle;
    private readonly ILogger<VciEndpointHandler> _logger;
    private readonly CredentialOfferService _offers;
    private readonly IAdapter<DeferredCredentialTransaction> _deferred;
    private readonly IAdapter<CredentialNotificationRecord> _notifications;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    public VciEndpointHandler(
        IOptions<ProviderOptions> options,
        VciService vciService,
        AccessTokenService accessTokens,
        RequestThrottle throttle,
        ILogger<VciEndpointHandler> logger,
        CredentialOfferService offers,
        IAdapter<DeferredCredentialTransaction> deferred,
        IAdapter<CredentialNotificationRecord> notifications)
    {
        _offers = offers;
        _deferred = deferred;
        _notifications = notifications;
        _throttle = throttle;
        _logger = logger;
        _options = options;
        _vciService = vciService;
        _accessTokens = accessTokens;
    }

    private static IResult Error(OAuthError err, int status) => Results.Json(err, statusCode: status);

    /// <summary><c>POST /connect/nonce</c> — issues a fresh c_nonce.</summary>
    public async Task<IResult> HandleNonceAsync(HttpContext context, CancellationToken ct)
    {
        if (!_options.Value.VciEnabled)
            return Error(OAuthError.InvalidRequest("VCI is not enabled"), 400);

        // Unauthenticated and stateful: every call stores a nonce, so budget it per caller.
        if (!_throttle.TryAcquireUnauthenticated(context))
            return RequestThrottle.TooManyRequests(context);

        var nonce = await _vciService.IssueNonceAsync(ct);
        return Results.Json(new
        {
            c_nonce = nonce,
            c_nonce_expires_in = _vciService.NonceLifetimeSeconds,
        });
    }

    /// <summary><c>POST /connect/credential</c> — validates an access token + proofs and issues credentials.</summary>
    public async Task<IResult> HandleCredentialAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.VciEnabled)
            return Error(OAuthError.InvalidRequest("VCI is not enabled"), 400);

        if (opts.IssueCredential is null)
            return Error(OAuthError.ServerError("Credential issuance is not configured"), 500);

        var (stored, tokenError) = await AuthenticateAsync(context, ct);
        if (tokenError is not null)
            return tokenError;

        var (root, bodyError) = await ReadJsonObjectAsync(context, OAuthError.InvalidCredentialRequest, ct);
        if (bodyError is not null)
            return bodyError;

        // Response encryption (credential_response_encryption) is not offered in the metadata.
        if (root.TryGetProperty("credential_response_encryption", out _))
            return Error(OAuthError.InvalidEncryptionParameters("credential response encryption is not supported"), 400);

        // ── Which credential (§8.2): credential_identifier XOR credential_configuration_id ──
        var identifiers = CredentialAuthorizationDetails.AuthorizedIdentifiers(stored!.AuthorizationDetailsJson);
        var identifier = StringProperty(root, "credential_identifier");
        var configId = StringProperty(root, "credential_configuration_id");
        if ((identifier is null) == (configId is null))
            return Error(OAuthError.InvalidCredentialRequest(
                "exactly one of credential_identifier and credential_configuration_id is required"), 400);

        if (identifier is not null)
        {
            if (!identifiers.TryGetValue(identifier, out configId))
                return Error(OAuthError.UnknownCredentialIdentifier($"unknown credential_identifier '{identifier}'"), 400);
        }
        else if (identifiers.ContainsValue(configId!))
        {
            // Tokens whose authorization details carry identifiers must be redeemed by identifier.
            return Error(OAuthError.InvalidCredentialRequest(
                "the access token lists credential_identifiers; request by credential_identifier"), 400);
        }

        var config = opts.VciCredentialConfigurations.FirstOrDefault(c => c.Id == configId);
        if (config is null)
            return Error(OAuthError.UnknownCredentialConfiguration($"unknown credential_configuration_id '{configId}'"), 400);

        // The token must have been granted this credential, by scope or by authorization details.
        var byScope = config.Scope is not null && stored.Scopes.Contains(config.Scope);
        if (!byScope && !identifiers.ContainsValue(config.Id))
        {
            context.Response.Headers.WWWAuthenticate = config.Scope is null
                ? "Bearer realm=\"NetOidc\", error=\"insufficient_scope\""
                : $"Bearer realm=\"NetOidc\", error=\"insufficient_scope\", scope=\"{config.Scope}\"";
            return Error(OAuthError.InsufficientScope($"access token does not authorize credential '{config.Id}'"), 403);
        }

        // ── Key proofs (OID4VCI 1.0 §8.2) ────────────────────────────────────
        var (holderKeys, proofError) = await VerifyProofsAsync(root, config, stored, opts);
        if (proofError is not null)
            return proofError;

        var request = new CredentialIssuanceRequest(stored.Subject!, config.Id, stored.ClientId, stored.Scopes, holderKeys);
        var (result, issueError) = await InvokeAsync(() => opts.IssueCredential(request, ct), config.Id);
        if (issueError is not null)
            return issueError;

        if (result!.IsDeferred)
        {
            if (opts.RetrieveDeferredCredential is null)
            {
                _logger.LogError("IssueCredential deferred {ConfigurationId} but RetrieveDeferredCredential is not configured", config.Id);
                return Error(OAuthError.ServerError("credential issuance failed"), 500);
            }
            var transactionId = NewId();
            var lifetime = TimeSpan.FromSeconds(opts.VciDeferredTransactionLifetimeSeconds);
            await _deferred.StoreAsync(transactionId, new DeferredCredentialTransaction
            {
                TransactionId = transactionId,
                ClientId = stored.ClientId,
                Subject = stored.Subject!,
                CredentialConfigurationId = config.Id,
                Scopes = stored.Scopes,
                HolderPublicJwks = holderKeys,
                ExpiresAt = DateTimeOffset.UtcNow + lifetime,
            }, lifetime, ct);
            return Deferred(transactionId, result.RetryAfter!.Value);
        }

        return await IssuedAsync(result, request, ct);
    }

    /// <summary><c>POST /connect/deferred_credential</c> — redeems a deferred issuance (OID4VCI 1.0 §9).</summary>
    public async Task<IResult> HandleDeferredCredentialAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.VciEnabled || opts.RetrieveDeferredCredential is null)
            return Results.NotFound();

        var (stored, tokenError) = await AuthenticateAsync(context, ct);
        if (tokenError is not null)
            return tokenError;

        var (root, bodyError) = await ReadJsonObjectAsync(context, OAuthError.InvalidCredentialRequest, ct);
        if (bodyError is not null)
            return bodyError;

        var transactionId = StringProperty(root, "transaction_id");
        if (transactionId is null)
            return Error(OAuthError.InvalidCredentialRequest("transaction_id is required"), 400);

        // A transaction is only visible to the client and End-User it was created for.
        var transaction = await _deferred.FindAsync(transactionId, ct);
        if (transaction is null || transaction.ExpiresAt <= DateTimeOffset.UtcNow ||
            transaction.ClientId != stored!.ClientId || transaction.Subject != stored.Subject)
            return Error(OAuthError.InvalidTransactionId(), 400);

        var request = new CredentialIssuanceRequest(transaction.Subject, transaction.CredentialConfigurationId,
            transaction.ClientId, transaction.Scopes, transaction.HolderPublicJwks);
        var (result, issueError) = await InvokeAsync(
            () => opts.RetrieveDeferredCredential(new DeferredCredentialRequest(transactionId, request), ct),
            transaction.CredentialConfigurationId);
        if (issueError is not null)
            return issueError;

        if (result!.IsDeferred)
            return Deferred(transactionId, result.RetryAfter!.Value);

        // Single use: a concurrent redemption that lost the race gets invalid_transaction_id.
        if (await _deferred.ConsumeAsync(transactionId, ct) is null)
            return Error(OAuthError.InvalidTransactionId(), 400);
        return await IssuedAsync(result, request, ct);
    }

    /// <summary><c>POST /connect/notification</c> — the wallet reports the fate of issued credentials (OID4VCI 1.0 §11).</summary>
    public async Task<IResult> HandleNotificationAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.VciEnabled || opts.OnCredentialNotification is null)
            return Results.NotFound();

        var (stored, tokenError) = await AuthenticateAsync(context, ct);
        if (tokenError is not null)
            return tokenError;

        var (root, bodyError) = await ReadJsonObjectAsync(context, OAuthError.InvalidNotificationRequest, ct);
        if (bodyError is not null)
            return bodyError;

        var notificationId = StringProperty(root, "notification_id");
        var @event = StringProperty(root, "event");
        if (notificationId is null || @event is not ("credential_accepted" or "credential_failure" or "credential_deleted"))
            return Error(OAuthError.InvalidNotificationRequest(
                "notification_id and an event of credential_accepted, credential_failure or credential_deleted are required"), 400);

        var record = await _notifications.FindAsync(notificationId, ct);
        if (record is null || record.ExpiresAt <= DateTimeOffset.UtcNow ||
            record.ClientId != stored!.ClientId || record.Subject != stored.Subject)
            return Error(OAuthError.InvalidNotificationId(), 400);

        try
        {
            await opts.OnCredentialNotification(new CredentialNotification(notificationId, @event,
                StringProperty(root, "event_description"), record.ClientId, record.Subject, record.CredentialConfigurationId), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "OnCredentialNotification failed for {NotificationId}", notificationId);
            return Error(OAuthError.ServerError(), 500);
        }
        return Results.NoContent();
    }

    /// <summary><c>GET /connect/credential_offer/{id}</c> — serves an offer by reference (OID4VCI 1.0 §4.1.3).</summary>
    public async Task<IResult> HandleCredentialOfferAsync(string offerId, CancellationToken ct)
    {
        if (!_options.Value.VciEnabled)
            return Results.NotFound();
        return await _offers.FindOfferAsync(offerId, ct) is { } offer
            ? Results.Content(offer, "application/json")
            : Results.NotFound();
    }

    private async Task<(AccessToken? Token, IResult? Error)> AuthenticateAsync(HttpContext context, CancellationToken ct)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return (null, InvalidToken(context));

        var live = await _accessTokens.ValidateAsync(authHeader["Bearer ".Length..].Trim(), ct);
        if (live is null)
            return (null, InvalidToken(context));   // invalid, expired or revoked

        // Credentials describe an End-User; a client-only token cannot obtain one.
        if (string.IsNullOrEmpty(live.Record.Subject))
            return (null, InvalidToken(context, "access token has no End-User subject"));
        return (live.Record, null);
    }

    private static async Task<(JsonElement Root, IResult? Error)> ReadJsonObjectAsync(
        HttpContext context, Func<string?, OAuthError> error, CancellationToken ct)
    {
        if (!context.Request.HasJsonContentType())
            return (default, Error(error("Content-Type must be application/json"), 400));
        try
        {
            using var body = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: ct);
            return body.RootElement.ValueKind == JsonValueKind.Object
                ? (body.RootElement.Clone(), null)
                : (default, Error(error("Request body must be a JSON object"), 400));
        }
        catch (JsonException)
        {
            return (default, Error(error("Invalid JSON body"), 400));
        }
    }

    private async Task<(CredentialIssuanceResult? Result, IResult? Error)> InvokeAsync(
        Func<Task<CredentialIssuanceResult>> hook, string configId)
    {
        try
        {
            return (await hook(), null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never echo hook exception details to the wallet.
            _logger.LogError(ex, "Credential issuance hook failed for configuration {ConfigurationId}", configId);
            return (null, Error(OAuthError.ServerError("credential issuance failed"), 500));
        }
    }

    /// <summary>The credential response (§8.3): one credential per proven key, plus a notification_id.</summary>
    private async Task<IResult> IssuedAsync(CredentialIssuanceResult result, CredentialIssuanceRequest request, CancellationToken ct)
    {
        var opts = _options.Value;
        if (request.HolderPublicJwks.Count > 0 && result.Credentials.Count != request.HolderPublicJwks.Count)
        {
            _logger.LogError("Credential issuance for {ConfigurationId} returned {Issued} credentials for {Keys} holder keys",
                request.CredentialConfigurationId, result.Credentials.Count, request.HolderPublicJwks.Count);
            return Error(OAuthError.ServerError("credential issuance failed"), 500);
        }

        var body = new Dictionary<string, object>
        {
            ["credentials"] = result.Credentials.Select(c => new Dictionary<string, object> { ["credential"] = c }).ToArray(),
        };
        if (opts.OnCredentialNotification is not null)
        {
            var notificationId = NewId();
            var lifetime = TimeSpan.FromSeconds(opts.VciNotificationLifetimeSeconds);
            await _notifications.StoreAsync(notificationId, new CredentialNotificationRecord
            {
                NotificationId = notificationId,
                ClientId = request.ClientId,
                Subject = request.Subject,
                CredentialConfigurationId = request.CredentialConfigurationId,
                ExpiresAt = DateTimeOffset.UtcNow + lifetime,
            }, lifetime, ct);
            body["notification_id"] = notificationId;
        }
        return Results.Json(body);
    }

    private static IResult Deferred(string transactionId, TimeSpan retryAfter) =>
        Results.Json(new Dictionary<string, object>
        {
            ["transaction_id"] = transactionId,
            ["interval"] = (int)Math.Ceiling(retryAfter.TotalSeconds),
        }, statusCode: StatusCodes.Status202Accepted);

    private static string? StringProperty(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } s
            ? s : null;

    private static string NewId() => Base64UrlEncoder.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));

    /// <summary>
    /// Verifies every proof in the request and returns the proven holder keys.
    /// Accepts the single <c>proof</c> object and the <c>proofs</c> batch form.
    /// </summary>
    private async Task<(IReadOnlyList<string> HolderKeys, IResult? Error)> VerifyProofsAsync(
        JsonElement root, CredentialConfiguration config, AccessToken token, ProviderOptions opts)
    {
        var proofJwts = new List<string>();

        if (root.TryGetProperty("proof", out var proofEl))
        {
            if (proofEl.ValueKind != JsonValueKind.Object)
                return ([], Error(OAuthError.InvalidProof("proof must be an object"), 400));
            var proofType = proofEl.TryGetProperty("proof_type", out var pt) ? pt.GetString() : null;
            if (proofType != "jwt")
                return ([], Error(OAuthError.InvalidProof($"unsupported proof_type '{proofType}'"), 400));
            var jwt = proofEl.TryGetProperty("jwt", out var pj) ? pj.GetString() : null;
            if (string.IsNullOrEmpty(jwt))
                return ([], Error(OAuthError.InvalidProof("proof.jwt is required when proof_type is jwt"), 400));
            proofJwts.Add(jwt);
        }

        if (root.TryGetProperty("proofs", out var proofsEl))
        {
            if (proofJwts.Count > 0)
                return ([], Error(OAuthError.InvalidRequest("proof and proofs must not both be present"), 400));
            if (proofsEl.ValueKind != JsonValueKind.Object ||
                !proofsEl.TryGetProperty("jwt", out var arr) || arr.ValueKind != JsonValueKind.Array)
                return ([], Error(OAuthError.InvalidProof("proofs must contain a jwt array"), 400));
            foreach (var item in arr.EnumerateArray())
            {
                var jwt = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
                if (string.IsNullOrEmpty(jwt))
                    return ([], Error(OAuthError.InvalidProof("proofs.jwt entries must be non-empty strings"), 400));
                proofJwts.Add(jwt);
            }
        }

        var bindingRequired = config.CryptographicBindingMethodsSupported.Count > 0;
        if (proofJwts.Count == 0)
            return bindingRequired
                ? ([], Error(OAuthError.InvalidProof("a key proof is required for this credential"), 400))
                : ([], null);

        if (proofJwts.Count > Math.Max(1, opts.VciBatchSize))
            return ([], Error(OAuthError.InvalidProof($"at most {Math.Max(1, opts.VciBatchSize)} proofs are accepted"), 400));

        if (!config.ProofTypesSupported.TryGetValue("jwt", out var allowedAlgs))
            return ([], Error(OAuthError.InvalidProof("jwt proofs are not supported for this credential"), 400));

        var credIssuer = VciService.CredentialIssuer(opts);

        var holderKeys = new List<string>(proofJwts.Count);
        foreach (var proofJwt in proofJwts)
        {
            var (key, error) = await VerifyProofJwtAsync(proofJwt, allowedAlgs, credIssuer, token.ClientId);
            if (error is not null)
                return ([], error);
            holderKeys.Add(key!);
        }

        return (holderKeys, null);
    }

    private async Task<(string? HolderJwk, IResult? Error)> VerifyProofJwtAsync(
        string proofJwt, IReadOnlyList<string> allowedAlgs, string credIssuer, string clientId)
    {
        JsonWebToken token;
        try { token = _jwtHandler.ReadJsonWebToken(proofJwt); }
        catch { return (null, Error(OAuthError.InvalidProof("proof JWT is malformed"), 400)); }

        if (!string.Equals(token.Typ, ProofTyp, StringComparison.Ordinal))
            return (null, Error(OAuthError.InvalidProof($"proof JWT typ must be {ProofTyp}"), 400));

        // Asymmetric algorithms from the configuration only; never none or HMAC.
        if (string.IsNullOrEmpty(token.Alg) || token.Alg == "none" ||
            token.Alg.StartsWith("HS", StringComparison.Ordinal) || !allowedAlgs.Contains(token.Alg))
            return (null, Error(OAuthError.InvalidProof($"proof JWT alg '{token.Alg}' is not supported"), 400));

        // Only the jwk binding method is implemented; kid (DID) and x5c are refused explicitly.
        var embedded = EmbeddedJwk.FromHeader(token.EncodedHeader);
        if (embedded is null)
            return (null, Error(OAuthError.InvalidProof("proof JWT must carry a public jwk header"), 400));

        var result = await _jwtHandler.ValidateTokenAsync(proofJwt, new TokenValidationParameters
        {
            IssuerSigningKey = embedded.Value.Key,
            ValidAlgorithms = [token.Alg],
            ValidTypes = [ProofTyp],
            ValidAudience = credIssuer,
            ValidateIssuer = false,         // iss is optional; checked below when present
            ValidateLifetime = false,       // proofs carry iat, not exp; checked below
            RequireExpirationTime = false,
        });
        if (!result.IsValid)
            return (null, Error(OAuthError.InvalidProof("proof JWT signature or audience is invalid"), 400));

        if (!string.IsNullOrEmpty(token.Issuer) && token.Issuer != clientId)
            return (null, Error(OAuthError.InvalidProof("proof JWT iss must be the client_id"), 400));

        if (!token.TryGetPayloadValue<long>("iat", out var iatUnix) ||
            (DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(iatUnix)).Duration() > ProofMaxAge)
            return (null, Error(OAuthError.InvalidProof("proof JWT iat is missing or not recent"), 400));

        // A fresh, single-use c_nonce defeats proof replay.
        if (!token.TryGetPayloadValue<string>("nonce", out var nonce) || string.IsNullOrEmpty(nonce) ||
            !await _vciService.ConsumeNonceAsync(nonce))
            return (null, Error(OAuthError.InvalidNonce("proof JWT must contain a valid c_nonce"), 400));

        return (embedded.Value.Json, null);
    }

    private static IResult InvalidToken(HttpContext context, string? description = null)
    {
        context.Response.Headers.WWWAuthenticate = "Bearer realm=\"NetOidc\", error=\"invalid_token\"";
        return Error(OAuthError.InvalidToken(description), 401);
    }
}
