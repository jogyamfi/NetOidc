using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Dcr;

/// <summary>
/// Handles the Dynamic Client Registration (RFC 7591) and Client Configuration
/// Management (RFC 7592) endpoints:
/// <list type="bullet">
///   <item><c>POST   /connect/register</c> — register a new client</item>
///   <item><c>GET    /connect/register/{clientId}</c> — read client metadata</item>
///   <item><c>PUT    /connect/register/{clientId}</c> — update client metadata</item>
///   <item><c>DELETE /connect/register/{clientId}</c> — delete a dynamic client</item>
/// </list>
/// </summary>
internal sealed class DynamicRegistrationEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IDynamicClientStore _clientStore;
    private readonly RequestThrottle _throttle;
    private readonly ILogger<DynamicRegistrationEndpointHandler> _logger;
    private readonly Abstractions.Events.IProviderEventSink _events;
    private readonly SafeHttpFetcher _fetcher;
    private readonly Jose.KeyRing _keys;

    public DynamicRegistrationEndpointHandler(
        IOptions<ProviderOptions> options,
        IDynamicClientStore clientStore,
        RequestThrottle throttle,
        ILogger<DynamicRegistrationEndpointHandler> logger,
        Abstractions.Events.IProviderEventSink events,
        SafeHttpFetcher fetcher,
        Jose.KeyRing keys)
    {
        _fetcher = fetcher;
        _keys = keys;
        _events = events;
        _logger = logger;
        _throttle = throttle;
        _options = options;
        _clientStore = clientStore;
    }

    // ── POST /connect/register ───────────────────────────────────────────────

    public async Task<IResult> HandleCreateAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.DcrEnabled)
            return DcrError(OAuthError.InvalidRequest("Dynamic client registration is disabled"), 400);

        // Registration may be open to anyone; budget it per caller.
        if (!_throttle.TryAcquireUnauthenticated(context))
            return RequestThrottle.TooManyRequests(context);

        // Validate initial access token when required.
        if (opts.InitialAccessToken is not null)
        {
            var bearer = ExtractBearer(context);
            if (bearer is null || !CryptographicEquals(bearer, opts.InitialAccessToken))
                return DcrError(OAuthError.InvalidRequest("Invalid or missing initial_access_token"), 401);
        }

        if (!context.Request.HasJsonContentType())
            return DcrError(OAuthError.InvalidRequest("Content-Type must be application/json"), 415);

        ClientRegistrationRequest? req;
        try
        {
            req = await context.Request.ReadFromJsonAsync<ClientRegistrationRequest>(ct);
        }
        catch
        {
            return DcrError(OAuthError.InvalidRequest("Could not parse registration request"), 400);
        }

        if (req is null)
            return DcrError(OAuthError.InvalidRequest("Empty registration request"), 400);

        var (client, registrationToken, validationError) = await BuildClientAsync(opts, req, existing: null, ct);
        if (validationError is not null)
            return DcrError(validationError, 400);

        // Run optional validation hook.
        if (opts.ValidateDynamicClient is not null)
        {
            if (await RunValidationHookAsync(opts, client!, ct) is { } hookError)
                return hookError;
        }

        await _clientStore.StoreClientAsync(client!, ct);
        await RecordChangeAsync(client!.ClientId, "created", ct);

        return Results.Json(BuildResponse(opts, client!, registrationToken), statusCode: 201);
    }

    // ── GET /connect/register/{clientId} ────────────────────────────────────

    public async Task<IResult> HandleGetAsync(
        HttpContext context, string clientId, CancellationToken ct)
    {
        var client = await AuthorizeManagementAsync(context, clientId, ct);
        if (client is null) return DcrError(OAuthError.InvalidClient("unauthorized"), 401);

        return Results.Json(BuildResponse(_options.Value, client, registrationToken: null));
    }

    // ── PUT /connect/register/{clientId} ────────────────────────────────────

    public async Task<IResult> HandleUpdateAsync(
        HttpContext context, string clientId, CancellationToken ct)
    {
        var existing = await AuthorizeManagementAsync(context, clientId, ct);
        if (existing is null) return DcrError(OAuthError.InvalidClient("unauthorized"), 401);

        if (!context.Request.HasJsonContentType())
            return DcrError(OAuthError.InvalidRequest("Content-Type must be application/json"), 415);

        ClientRegistrationRequest? req;
        try { req = await context.Request.ReadFromJsonAsync<ClientRegistrationRequest>(ct); }
        catch { return DcrError(OAuthError.InvalidRequest("Could not parse update request"), 400); }

        if (req is null)
            return DcrError(OAuthError.InvalidRequest("Empty update request"), 400);

        var opts = _options.Value;
        var (final, registrationToken, validationError) = await BuildClientAsync(opts, req, existing, ct);
        if (validationError is not null)
            return DcrError(validationError, 400);

        if (opts.ValidateDynamicClient is not null)
        {
            if (await RunValidationHookAsync(opts, final!, ct) is { } hookError)
                return hookError;
        }

        await _clientStore.StoreClientAsync(final!, ct);
        await RecordChangeAsync(final!.ClientId, "updated", ct);

        return Results.Json(BuildResponse(opts, final, registrationToken));
    }

    // ── DELETE /connect/register/{clientId} ─────────────────────────────────

    public async Task<IResult> HandleDeleteAsync(
        HttpContext context, string clientId, CancellationToken ct)
    {
        var client = await AuthorizeManagementAsync(context, clientId, ct);
        if (client is null) return DcrError(OAuthError.InvalidClient("unauthorized"), 401);

        await _clientStore.RemoveClientAsync(clientId, ct);
        await RecordChangeAsync(clientId, "deleted", ct);
        return Results.NoContent();
    }

    private async Task RecordChangeAsync(string clientId, string change, CancellationToken ct)
    {
        Diagnostics.Log.ClientRegistrationChanged(_logger, clientId, change);
        await _events.ClientRegistrationChangedAsync(
            new Abstractions.Events.ClientRegistrationChangedEvent(clientId, change, DateTimeOffset.UtcNow), ct);
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// <summary>Validates the Bearer registration_access_token and returns the client, or null.</summary>
    private async Task<Client?> AuthorizeManagementAsync(
        HttpContext context, string clientId, CancellationToken ct)
    {
        var bearer = ExtractBearer(context);
        if (bearer is null) return null;

        var client = await _clientStore.FindClientAsync(clientId, ct);
        if (client is null || !client.IsDynamic) return null;

        if (client.RegistrationAccessTokenHash is null) return null;

        var incoming = HashToken(bearer);
        return CryptographicEquals(incoming, client.RegistrationAccessTokenHash) ? client : null;
    }

    /// <summary>Token endpoint authentication methods dynamic clients may register.</summary>
    private static readonly string[] DcrAuthMethods =
        ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"];

    /// <summary>
    /// Builds a client from registration metadata. On update (<paramref name="existing"/> set) the
    /// client id and issue time are kept, and the registration access token unless rotation is on;
    /// the returned token is then <c>null</c>.
    /// </summary>
    private async Task<(Client? Client, string? RegistrationToken, OAuthError? Error)> BuildClientAsync(
        ProviderOptions opts, ClientRegistrationRequest req, Client? existing, CancellationToken ct)
    {
        var (authMethod, authError) = Choose("token_endpoint_auth_method", req.TokenEndpointAuthMethod,
            req.TokenEndpointAuthMethodsSupported, DcrAuthMethods.Contains, "client_secret_basic");
        if (authError is not null)
            return (null, null, authError);

        // ── Client keys (RFC 7591 §2): inline jwks or a jwks_uri, never both ──
        if (req.Jwks is not null && req.JwksUri is not null)
            return (null, null, OAuthError.InvalidClientMetadata("jwks and jwks_uri must not both be present"));
        string? jwks = null;
        if (req.Jwks is { } inline)
            jwks = inline.ValueKind == System.Text.Json.JsonValueKind.Object ? inline.GetRawText() : null;
        else if (req.JwksUri is not null)
        {
            if (ClientMetadataValidator.ValidateServerCallbackUri("jwks_uri", req.JwksUri, opts.DcrAllowPrivateNetworkUris) is { } jwksUriError)
                return (null, null, OAuthError.InvalidClientMetadata(jwksUriError));
            // Fetched now to validate it; re-fetched when a signature fails (ClientJwksProvider).
            jwks = (await _fetcher.GetAsync(req.JwksUri, MaxJwksBytes, "application/json", ct,
                opts.DcrAllowPrivateNetworkUris))?.Content;
            if (jwks is null)
                return (null, null, OAuthError.InvalidClientMetadata("jwks_uri could not be fetched"));
        }
        if ((req.Jwks is not null || req.JwksUri is not null) && !IsPublicKeySet(jwks))
            return (null, null, OAuthError.InvalidClientMetadata("jwks must be a JWK Set of public keys"));
        // request_uris (OIDC Registration §2): fetched by the provider, so https and SSRF rules apply.
        foreach (var requestUri in req.RequestUris ?? [])
        {
            if (ClientMetadataValidator.ValidateServerCallbackUri("request_uris", requestUri.Split('#', 2)[0],
                    opts.DcrAllowPrivateNetworkUris) is { } requestUriError)
                return (null, null, OAuthError.InvalidClientMetadata(requestUriError));
        }

        if (authMethod == "private_key_jwt" && jwks is null)
            return (null, null, OAuthError.InvalidClientMetadata("private_key_jwt requires jwks or jwks_uri"));

        // ── Algorithms: the provider signs with keys it holds; the client signs and decrypts ──
        bool CanSign(string alg) => _keys.CanSignWith(alg);
        bool ClientCanSign(string alg) => Jose.KeyRing.SupportedSigningAlgorithms.Contains(alg);
        bool KeyAlg(string alg) => Jose.KeyRing.SupportedEncryptionAlgorithms.Contains(alg);
        bool ContentAlg(string enc) => Jose.KeyRing.SupportedContentEncryptionAlgorithms.Contains(enc);

        var (idTokenAlg, e1) = Choose("id_token_signed_response_alg", req.IdTokenSignedResponseAlg, req.IdTokenSigningAlgValuesSupported, CanSign);
        var (userInfoAlg, e2) = Choose("userinfo_signed_response_alg", req.UserInfoSignedResponseAlg, req.UserInfoSigningAlgValuesSupported, CanSign);
        var (authorizationAlg, e3) = Choose("authorization_signed_response_alg", req.AuthorizationSignedResponseAlg, req.AuthorizationSigningAlgValuesSupported, CanSign);
        var (requestObjectAlg, e4) = Choose("request_object_signing_alg", req.RequestObjectSigningAlg, req.RequestObjectSigningAlgValuesSupported, ClientCanSign);
        var (idTokenEncAlg, e5) = Choose("id_token_encrypted_response_alg", req.IdTokenEncryptedResponseAlg, req.IdTokenEncryptionAlgValuesSupported, KeyAlg);
        var (idTokenEnc, e6) = Choose("id_token_encrypted_response_enc", req.IdTokenEncryptedResponseEnc, req.IdTokenEncryptionEncValuesSupported, ContentAlg);
        var (userInfoEncAlg, e7) = Choose("userinfo_encrypted_response_alg", req.UserInfoEncryptedResponseAlg, req.UserInfoEncryptionAlgValuesSupported, KeyAlg);
        var (userInfoEnc, e8) = Choose("userinfo_encrypted_response_enc", req.UserInfoEncryptedResponseEnc, req.UserInfoEncryptionEncValuesSupported, ContentAlg);
        if (new[] { e1, e2, e3, e4, e5, e6, e7, e8 }.FirstOrDefault(e => e is not null) is { } algError)
            return (null, null, algError);

        // OIDC Registration §2: an enc without its alg is meaningless; alg alone defaults enc.
        if ((idTokenEnc is not null && idTokenEncAlg is null) || (userInfoEnc is not null && userInfoEncAlg is null))
            return (null, null, OAuthError.InvalidClientMetadata("*_encrypted_response_enc requires the matching *_encrypted_response_alg"));
        if (idTokenEncAlg is not null) idTokenEnc ??= "A128CBC-HS256";
        if (userInfoEncAlg is not null) userInfoEnc ??= "A128CBC-HS256";
        if ((idTokenEncAlg is not null || userInfoEncAlg is not null) && jwks is null)
            return (null, null, OAuthError.InvalidClientMetadata("encrypted responses require jwks or jwks_uri"));

        var grantTypes = (req.GrantTypes ?? ["authorization_code"]).Distinct().ToList();
        var disallowedGrants = grantTypes.Where(g => !opts.DcrAllowedGrantTypes.Contains(g)).ToList();
        if (disallowedGrants.Count > 0)
            return (null, null, OAuthError.InvalidClientMetadata(
                $"grant_types not permitted for dynamic registration: {string.Join(" ", disallowedGrants)}"));

        // RFC 7591 §2.1: response_types must be consistent with grant_types.
        var responseTypes = req.ResponseTypes?.ToList()
            ?? (grantTypes.Contains("authorization_code") ? ["code"] : []);
        foreach (var rt in responseTypes)
        {
            var parts = rt.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var needsCode = parts.Contains("code");
            var needsImplicit = parts.Any(p => p is "token" or "id_token");
            if (parts.Any(p => p is not ("code" or "token" or "id_token")) ||
                (needsCode && !grantTypes.Contains("authorization_code")) ||
                (needsImplicit && !grantTypes.Contains("implicit")))
                return (null, null, OAuthError.InvalidClientMetadata(
                    $"response_type '{rt}' is inconsistent with grant_types"));
        }

        // Redirect-based grants require at least one valid redirect URI.
        var redirectUris = req.RedirectUris ?? [];
        if (redirectUris.Count == 0 &&
            (grantTypes.Contains("authorization_code") || grantTypes.Contains("implicit")))
            return (null, null, OAuthError.InvalidRedirectUri("redirect_uris is required"));
        foreach (var uri in redirectUris)
        {
            if (ClientMetadataValidator.ValidateRedirectUri(uri) is { } err)
                return (null, null, OAuthError.InvalidRedirectUri(err));
        }

        foreach (var uri in req.PostLogoutRedirectUris ?? [])
        {
            if (ClientMetadataValidator.ValidateRedirectUri(uri) is { } err)
                return (null, null, OAuthError.InvalidClientMetadata("post_logout_redirect_uris: " + err));
        }

        if (req.ClientUri is not null &&
            ClientMetadataValidator.ValidateWebUri("client_uri", req.ClientUri) is { } clientUriErr)
            return (null, null, OAuthError.InvalidClientMetadata(clientUriErr));
        if (req.LogoUri is not null &&
            ClientMetadataValidator.ValidateWebUri("logo_uri", req.LogoUri) is { } logoErr)
            return (null, null, OAuthError.InvalidClientMetadata(logoErr));
        if (req.PolicyUri is not null &&
            ClientMetadataValidator.ValidateWebUri("policy_uri", req.PolicyUri) is { } policyErr)
            return (null, null, OAuthError.InvalidClientMetadata(policyErr));
        if (req.TosUri is not null &&
            ClientMetadataValidator.ValidateWebUri("tos_uri", req.TosUri) is { } tosErr)
            return (null, null, OAuthError.InvalidClientMetadata(tosErr));

        if (req.BackChannelLogoutUri is not null &&
            ClientMetadataValidator.ValidateServerCallbackUri(
                "backchannel_logout_uri", req.BackChannelLogoutUri, opts.DcrAllowPrivateNetworkUris) is { } bclErr)
            return (null, null, OAuthError.InvalidClientMetadata(bclErr));

        // PKCE is on by default and cannot be disabled by public clients (RFC 9700 §2.1.1).
        var requirePkce = req.RequirePkce ?? (opts.DcrRequirePkceByDefault || authMethod == "none");
        if (!requirePkce && authMethod == "none")
            return (null, null, OAuthError.InvalidClientMetadata("public clients must use PKCE"));

        // Build allowed scopes: intersect requested with registered scopes.
        var registeredScopes = opts.Scopes.Select(s => s.Name).ToHashSet();
        List<string> allowedScopes;
        if (req.Scope is not null)
        {
            allowedScopes = req.Scope
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(registeredScopes.Contains)
                .ToList();
        }
        else
        {
            allowedScopes = registeredScopes.ToList();
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        string? secret = null;
        long secretExpiresAt = 0;
        if (authMethod is "client_secret_basic" or "client_secret_post" or "client_secret_jwt")
        {
            secret = GenerateToken(byteLength: 64);   // long enough for HS512 (RFC 7518 §3.2)
            secretExpiresAt = opts.ClientSecretLifetimeSeconds > 0
                ? now + opts.ClientSecretLifetimeSeconds
                : 0;
        }

        // The registration access token survives an update unless rotation is enabled.
        var keepToken = existing is not null && !opts.DcrRotateRegistrationTokens;
        var registrationToken = keepToken ? null : GenerateToken();
        var tokenHash = keepToken ? existing!.RegistrationAccessTokenHash : HashToken(registrationToken!);
        var id = existing?.ClientId ?? GenerateClientId();

        var client = new Client
        {
            ClientId = id,
            ClientSecret = secret,
            RedirectUris = redirectUris,
            AllowedGrantTypes = grantTypes,
            AllowedScopes = allowedScopes,
            TokenEndpointAuthMethod = authMethod!,
            RequirePkce = requirePkce,
            ResponseTypes = responseTypes,
            // Dynamically registered clients are third parties: always ask the End-User.
            RequireConsent = true,
            IsDynamic = true,
            RegistrationAccessTokenHash = tokenHash,
            ClientIdIssuedAt = existing?.ClientIdIssuedAt ?? now,
            ClientSecretExpiresAt = secretExpiresAt,
            ClientName = req.ClientName,
            ClientUri = req.ClientUri,
            LogoUri = req.LogoUri,
            PolicyUri = req.PolicyUri,
            TosUri = req.TosUri,
            Contacts = req.Contacts ?? [],
            BackChannelLogoutUri = req.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = req.BackChannelLogoutSessionRequired ?? false,
            PostLogoutRedirectUris = req.PostLogoutRedirectUris ?? [],
            JwksJson = jwks,
            JwksUri = req.JwksUri,
            RequestUris = req.RequestUris ?? [],
            IdTokenSignedResponseAlg = idTokenAlg,
            IdTokenEncryptedResponseAlg = idTokenEncAlg,
            IdTokenEncryptedResponseEnc = idTokenEnc,
            UserInfoSignedResponseAlg = userInfoAlg,
            UserInfoEncryptedResponseAlg = userInfoEncAlg,
            UserInfoEncryptedResponseEnc = userInfoEnc,
            AuthorizationSignedResponseAlg = authorizationAlg,
            RequestObjectSigningAlg = requestObjectAlg,
            RequireSignedRequestObject = req.RequireSignedRequestObject ?? false,
        };

        return (client, registrationToken, null);
    }

    private const int MaxJwksBytes = 65536;

    /// <summary>
    /// Resolves a metadata value from the singular parameter or, per OpenID Connect RP Metadata
    /// Choices 1.0, from the RP's list of supported values (first one the provider supports).
    /// The singular parameter wins when both are sent.
    /// </summary>
    private static (string? Value, OAuthError? Error) Choose(
        string name, string? single, IReadOnlyList<string>? choices, Func<string, bool> supported, string? fallback = null)
    {
        if (single is not null)
            return supported(single)
                ? (single, null)
                : (null, OAuthError.InvalidClientMetadata($"{name} '{single}' is not supported"));
        if (choices is not null)
            return choices.FirstOrDefault(supported) is { } chosen
                ? (chosen, null)
                : (null, OAuthError.InvalidClientMetadata($"none of the offered {name} values is supported"));
        return (fallback, null);
    }

    private static bool IsPublicKeySet(string? json)
    {
        if (Federation.EntityStatement.TryJwks(json ?? string.Empty) is not { Keys.Count: > 0 } set)
            return false;
        return set.Keys.All(k => string.IsNullOrEmpty(k.D) && string.IsNullOrEmpty(k.K) && k.Kty is "RSA" or "EC" or "OKP");
    }

    private static ClientRegistrationResponse BuildResponse(
        ProviderOptions opts, Client client, string? registrationToken)
    {
        var issuer = opts.Issuer.TrimEnd('/');
        var scope = string.Join(" ", client.AllowedScopes);
        return new ClientRegistrationResponse
        {
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            ClientIdIssuedAt = client.ClientIdIssuedAt,
            ClientSecretExpiresAt = client.ClientSecretExpiresAt,
            RegistrationAccessToken = registrationToken,
            RegistrationClientUri = $"{issuer}{opts.RegistrationEndpoint}/{client.ClientId}",
            TokenEndpointAuthMethod = client.TokenEndpointAuthMethod,
            GrantTypes = client.AllowedGrantTypes,
            ResponseTypes = client.ResponseTypes,
            RedirectUris = client.RedirectUris,
            Scope = scope,
            ClientName = client.ClientName,
            ClientUri = client.ClientUri,
            LogoUri = client.LogoUri,
            PolicyUri = client.PolicyUri,
            TosUri = client.TosUri,
            Contacts = client.Contacts.Count > 0 ? client.Contacts : null,
            BackChannelLogoutUri = client.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = client.BackChannelLogoutSessionRequired,
            PostLogoutRedirectUris = client.PostLogoutRedirectUris.Count > 0 ? client.PostLogoutRedirectUris : null,
            // Echo what was registered: the jwks_uri, or the inline set.
            Jwks = client.JwksUri is not null || client.JwksJson is null
                ? null
                : System.Text.Json.JsonDocument.Parse(client.JwksJson).RootElement.Clone(),
            JwksUri = client.JwksUri,
            RequestUris = client.RequestUris.Count > 0 ? client.RequestUris : null,
            IdTokenSignedResponseAlg = client.IdTokenSignedResponseAlg,
            IdTokenEncryptedResponseAlg = client.IdTokenEncryptedResponseAlg,
            IdTokenEncryptedResponseEnc = client.IdTokenEncryptedResponseEnc,
            UserInfoSignedResponseAlg = client.UserInfoSignedResponseAlg,
            UserInfoEncryptedResponseAlg = client.UserInfoEncryptedResponseAlg,
            UserInfoEncryptedResponseEnc = client.UserInfoEncryptedResponseEnc,
            RequestObjectSigningAlg = client.RequestObjectSigningAlg,
            AuthorizationSignedResponseAlg = client.AuthorizationSignedResponseAlg,
            RequireSignedRequestObject = client.RequireSignedRequestObject,
        };
    }

    private static string? ExtractBearer(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        return auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? auth["Bearer ".Length..].Trim()
            : null;
    }

    internal static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static bool CryptographicEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static string GenerateToken(int byteLength = 32) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(byteLength))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string GenerateClientId() =>
        "dyn_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();

    /// <summary>
    /// Runs <see cref="ProviderOptions.ValidateDynamicClient"/>. Only a
    /// <see cref="ClientMetadataValidationException"/> message reaches the client.
    /// </summary>
    private async Task<IResult?> RunValidationHookAsync(ProviderOptions opts, Client client, CancellationToken ct)
    {
        try
        {
            await opts.ValidateDynamicClient!(client, ct);
            return null;
        }
        catch (ClientMetadataValidationException ex)
        {
            return DcrError(OAuthError.InvalidClientMetadata(ex.Message), 400);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "ValidateDynamicClient rejected client {ClientId}", client.ClientId);
            return DcrError(OAuthError.InvalidClientMetadata("client metadata was rejected"), 400);
        }
    }

    private static IResult DcrError(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
