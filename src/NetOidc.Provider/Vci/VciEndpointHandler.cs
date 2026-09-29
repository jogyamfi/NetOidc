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
/// Handles the OID4VCI credential endpoint (<c>POST /connect/credential</c>)
/// and nonce endpoint (<c>POST /connect/nonce</c>).
/// </summary>
public sealed class VciEndpointHandler
{
    private const string ProofTyp = "openid4vci-proof+jwt";

    /// <summary>Maximum age / clock skew accepted for a proof's <c>iat</c>.</summary>
    private static readonly TimeSpan ProofMaxAge = TimeSpan.FromMinutes(5);

    private readonly IOptions<ProviderOptions> _options;
    private readonly VciService _vciService;
    private readonly AccessTokenService _accessTokens;
    private readonly RequestThrottle _throttle;
    private readonly ILogger<VciEndpointHandler> _logger;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    public VciEndpointHandler(
        IOptions<ProviderOptions> options,
        VciService vciService,
        AccessTokenService accessTokens,
        RequestThrottle throttle,
        ILogger<VciEndpointHandler> logger)
    {
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

    /// <summary><c>POST /connect/credential</c> — validates an access token + proof and issues a VC.</summary>
    public async Task<IResult> HandleCredentialAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.VciEnabled)
            return Error(OAuthError.InvalidRequest("VCI is not enabled"), 400);

        if (opts.IssueCredential is null)
            return Error(OAuthError.ServerError("Credential issuance is not configured"), 500);

        // ── Access token (OID4VCI 1.0 §8.1) ──────────────────────────────────
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return InvalidToken(context);

        var rawToken = authHeader["Bearer ".Length..].Trim();
        var live = await _accessTokens.ValidateAsync(rawToken, ct);
        if (live is null)
            return InvalidToken(context);   // invalid, expired or revoked
        var stored = live.Record;

        // Credentials describe an End-User; a client-only token cannot obtain one.
        if (string.IsNullOrEmpty(stored.Subject))
            return InvalidToken(context, "access token has no End-User subject");

        // ── Request body ─────────────────────────────────────────────────────
        if (!context.Request.HasJsonContentType())
            return Error(OAuthError.InvalidRequest("Content-Type must be application/json"), 400);

        JsonDocument body;
        try { body = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: ct); }
        catch { return Error(OAuthError.InvalidRequest("Invalid JSON body"), 400); }

        using (body)
        {
            var root = body.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Error(OAuthError.InvalidRequest("Request body must be a JSON object"), 400);

            var configId = root.TryGetProperty("credential_configuration_id", out var cid) &&
                           cid.ValueKind == JsonValueKind.String
                ? cid.GetString() : null;

            if (string.IsNullOrEmpty(configId))
                return Error(OAuthError.InvalidRequest("credential_configuration_id is required"), 400);

            var config = opts.VciCredentialConfigurations.FirstOrDefault(c => c.Id == configId);
            if (config is null)
                return Error(OAuthError.InvalidRequest($"Unknown credential_configuration_id: {configId}"), 400);

            // The token must have been granted for this credential type.
            if (config.Scope is not null && !stored.Scopes.Contains(config.Scope))
            {
                context.Response.Headers.WWWAuthenticate =
                    $"Bearer realm=\"NetOidc\", error=\"insufficient_scope\", scope=\"{config.Scope}\"";
                return Error(OAuthError.InsufficientScope(
                    $"access token does not grant scope '{config.Scope}'"), 403);
            }

            // ── Key proofs (OID4VCI 1.0 §8.2) ────────────────────────────────
            var (holderKeys, proofError) = await VerifyProofsAsync(root, config, stored, opts);
            if (proofError is not null)
                return proofError;

            string credential;
            try
            {
                credential = await opts.IssueCredential(
                    new CredentialIssuanceRequest(
                        stored.Subject, configId, stored.ClientId, stored.Scopes, holderKeys), ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Never echo hook exception details to the wallet.
                _logger.LogError(ex, "IssueCredential failed for configuration {ConfigurationId}", configId);
                return Error(OAuthError.ServerError("credential issuance failed"), 500);
            }

            return Results.Json(new { credential });
        }
    }

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

        if (!config.ProofTypesSupported.TryGetValue("jwt", out var allowedAlgs))
            return ([], Error(OAuthError.InvalidProof("jwt proofs are not supported for this credential"), 400));

        var credIssuer = (string.IsNullOrEmpty(opts.VciCredentialIssuer) ? opts.Issuer : opts.VciCredentialIssuer)
            .TrimEnd('/');

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
