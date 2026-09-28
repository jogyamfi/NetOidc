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
public sealed class DynamicRegistrationEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IDynamicClientStore _clientStore;
    private readonly RequestThrottle _throttle;
    private readonly ILogger<DynamicRegistrationEndpointHandler> _logger;

    public DynamicRegistrationEndpointHandler(
        IOptions<ProviderOptions> options,
        IDynamicClientStore clientStore,
        RequestThrottle throttle,
        ILogger<DynamicRegistrationEndpointHandler> logger)
    {
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

        var (client, registrationToken, validationError) = BuildClient(opts, req, clientId: null);
        if (validationError is not null)
            return DcrError(validationError, 400);

        // Run optional validation hook.
        if (opts.ValidateDynamicClient is not null)
        {
            if (await RunValidationHookAsync(opts, client!, ct) is { } hookError)
                return hookError;
        }

        await _clientStore.StoreClientAsync(client!, ct);

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
        var (updated, newRegistrationToken, validationError) = BuildClient(opts, req, clientId: existing.ClientId);
        if (validationError is not null)
            return DcrError(validationError, 400);

        // Preserve the existing registration token hash unless rotation is enabled.
        string? registrationToken = null;
        string? tokenHash = existing.RegistrationAccessTokenHash;
        if (opts.DcrRotateRegistrationTokens)
        {
            registrationToken = newRegistrationToken;
            tokenHash = HashToken(registrationToken!);
        }

        // Rebuild with preserved immutable fields (Client is a class, not a record).
        var final = new Client
        {
            ClientId = existing.ClientId,
            ClientSecret = updated!.ClientSecret,
            RedirectUris = updated.RedirectUris,
            AllowedGrantTypes = updated.AllowedGrantTypes,
            AllowedScopes = updated.AllowedScopes,
            TokenEndpointAuthMethod = updated.TokenEndpointAuthMethod,
            RequirePkce = updated.RequirePkce,
            IsDynamic = true,
            RegistrationAccessTokenHash = tokenHash,
            ClientIdIssuedAt = existing.ClientIdIssuedAt,
            ClientSecretExpiresAt = updated.ClientSecretExpiresAt,
            ClientName = updated.ClientName,
            ClientUri = updated.ClientUri,
            LogoUri = updated.LogoUri,
            Contacts = updated.Contacts,
            BackChannelLogoutUri = updated.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = updated.BackChannelLogoutSessionRequired,
            PostLogoutRedirectUris = updated.PostLogoutRedirectUris,
        };

        if (opts.ValidateDynamicClient is not null)
        {
            if (await RunValidationHookAsync(opts, final, ct) is { } hookError)
                return hookError;
        }

        await _clientStore.StoreClientAsync(final, ct);

        return Results.Json(BuildResponse(opts, final, registrationToken));
    }

    // ── DELETE /connect/register/{clientId} ─────────────────────────────────

    public async Task<IResult> HandleDeleteAsync(
        HttpContext context, string clientId, CancellationToken ct)
    {
        var client = await AuthorizeManagementAsync(context, clientId, ct);
        if (client is null) return DcrError(OAuthError.InvalidClient("unauthorized"), 401);

        await _clientStore.RemoveClientAsync(clientId, ct);
        return Results.NoContent();
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

    private static (Client? Client, string? RegistrationToken, OAuthError? Error) BuildClient(
        ProviderOptions opts, ClientRegistrationRequest req, string? clientId)
    {
        var authMethod = req.TokenEndpointAuthMethod ?? "client_secret_basic";
        if (authMethod is not ("client_secret_basic" or "client_secret_post" or "none"))
            return (null, null, OAuthError.InvalidClientMetadata(
                $"Unsupported token_endpoint_auth_method: {authMethod}"));

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

        if (req.BackChannelLogoutUri is not null &&
            ClientMetadataValidator.ValidateServerCallbackUri(
                "backchannel_logout_uri", req.BackChannelLogoutUri, opts.DcrAllowPrivateNetworkUris) is { } bclErr)
            return (null, null, OAuthError.InvalidClientMetadata(bclErr));

        // PKCE is on by default and cannot be disabled by public clients (RFC 9700 §2.1.1).
        var requirePkce = req.RequirePkce ?? true;
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
        if (authMethod != "none")
        {
            secret = GenerateToken(byteLength: 64);   // long enough for HS512 (RFC 7518 §3.2)
            secretExpiresAt = opts.ClientSecretLifetimeSeconds > 0
                ? now + opts.ClientSecretLifetimeSeconds
                : 0;
        }

        var registrationToken = GenerateToken();
        var id = clientId ?? GenerateClientId();

        var client = new Client
        {
            ClientId = id,
            ClientSecret = secret,
            RedirectUris = redirectUris,
            AllowedGrantTypes = grantTypes,
            AllowedScopes = allowedScopes,
            TokenEndpointAuthMethod = authMethod,
            RequirePkce = requirePkce,
            IsDynamic = true,
            RegistrationAccessTokenHash = HashToken(registrationToken),
            ClientIdIssuedAt = now,
            ClientSecretExpiresAt = secretExpiresAt,
            ClientName = req.ClientName,
            ClientUri = req.ClientUri,
            LogoUri = req.LogoUri,
            Contacts = req.Contacts ?? [],
            BackChannelLogoutUri = req.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = req.BackChannelLogoutSessionRequired ?? false,
            PostLogoutRedirectUris = req.PostLogoutRedirectUris ?? [],
        };

        return (client, registrationToken, null);
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
            ResponseTypes = DeriveResponseTypes(client.AllowedGrantTypes),
            RedirectUris = client.RedirectUris,
            Scope = scope,
            ClientName = client.ClientName,
            ClientUri = client.ClientUri,
            LogoUri = client.LogoUri,
            Contacts = client.Contacts.Count > 0 ? client.Contacts : null,
            BackChannelLogoutUri = client.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = client.BackChannelLogoutSessionRequired,
            PostLogoutRedirectUris = client.PostLogoutRedirectUris.Count > 0 ? client.PostLogoutRedirectUris : null,
        };
    }

    private static IReadOnlyList<string> DeriveResponseTypes(IReadOnlyList<string> grantTypes)
    {
        var types = new HashSet<string>();
        foreach (var g in grantTypes)
        {
            if (g == "authorization_code") types.Add("code");
            if (g == "implicit") { types.Add("token"); types.Add("id_token"); }
        }
        return types.Count > 0 ? [.. types] : ["code"];
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
