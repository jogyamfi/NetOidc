using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;

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

    public DynamicRegistrationEndpointHandler(
        IOptions<ProviderOptions> options,
        IDynamicClientStore clientStore)
    {
        _options = options;
        _clientStore = clientStore;
    }

    // ── POST /connect/register ───────────────────────────────────────────────

    public async Task<IResult> HandleCreateAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.DcrEnabled)
            return DcrError(OAuthError.InvalidRequest("Dynamic client registration is disabled"), 400);

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
            return DcrError(OAuthError.InvalidRequest(validationError), 400);

        // Run optional validation hook.
        if (opts.ValidateDynamicClient is not null)
        {
            try { await opts.ValidateDynamicClient(client!, ct); }
            catch (Exception ex)
            {
                return DcrError(OAuthError.InvalidRequest(ex.Message), 400);
            }
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
            return DcrError(OAuthError.InvalidRequest(validationError), 400);

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
            try { await opts.ValidateDynamicClient(final, ct); }
            catch (Exception ex) { return DcrError(OAuthError.InvalidRequest(ex.Message), 400); }
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

    private static (Client? Client, string? RegistrationToken, string? Error) BuildClient(
        ProviderOptions opts, ClientRegistrationRequest req, string? clientId)
    {
        var authMethod = req.TokenEndpointAuthMethod ?? "client_secret_basic";
        if (authMethod is not ("client_secret_basic" or "client_secret_post" or "none"))
            return (null, null, $"Unsupported token_endpoint_auth_method: {authMethod}");

        var grantTypes = req.GrantTypes?.ToList() ?? ["authorization_code"];
        var responseTypes = req.ResponseTypes?.ToList() ?? ["code"];

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
            secret = GenerateToken();
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
            RedirectUris = req.RedirectUris ?? [],
            AllowedGrantTypes = grantTypes,
            AllowedScopes = allowedScopes,
            TokenEndpointAuthMethod = authMethod,
            RequirePkce = req.RequirePkce ?? false,
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

    private static string GenerateToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string GenerateClientId() =>
        "dyn_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();

    private static IResult DcrError(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
