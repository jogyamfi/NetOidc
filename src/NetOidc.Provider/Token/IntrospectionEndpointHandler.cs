using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Token;

/// <summary>
/// Handles the token introspection endpoint (RFC 7662).
/// Authenticates the caller as a client, then returns the status and metadata
/// of the submitted token.
/// </summary>
public sealed class IntrospectionEndpointHandler
{
    private readonly IClientStore _clientStore;
    private readonly IAdapter<AccessToken> _accessTokenStore;
    private readonly IAdapter<RefreshToken> _refreshTokenStore;
    private readonly TokenFactory _tokenFactory;
    private readonly IOptions<ProviderOptions> _options;

    public IntrospectionEndpointHandler(
        IClientStore clientStore,
        IAdapter<AccessToken> accessTokenStore,
        IAdapter<RefreshToken> refreshTokenStore,
        TokenFactory tokenFactory,
        IOptions<ProviderOptions> options)
    {
        _clientStore = clientStore;
        _accessTokenStore = accessTokenStore;
        _refreshTokenStore = refreshTokenStore;
        _tokenFactory = tokenFactory;
        _options = options;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        if (!context.Request.HasFormContentType)
            return Error(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var caller = await ClientAuthenticator.AuthenticateAsync(context, form, _clientStore, ct);
        if (caller is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return Error(OAuthError.InvalidClient(), 401);
        }

        var token = form["token"].ToString();
        if (string.IsNullOrEmpty(token))
            return Results.Json(new { active = false });

        var hint = form["token_type_hint"].ToString();

        // Try in hint order; if no hint, check access_token first then refresh_token.
        if (hint == "refresh_token")
            return await IntrospectRefreshTokenAsync(token, caller, ct)
                   ?? await IntrospectAccessTokenAsync(token, caller, ct)
                   ?? Inactive();

        return await IntrospectAccessTokenAsync(token, caller, ct)
               ?? await IntrospectRefreshTokenAsync(token, caller, ct)
               ?? Inactive();
    }

    // ── Per-type introspection ─────────────────────────────────────────────────

    private async Task<IResult?> IntrospectAccessTokenAsync(
        string token, Client caller, CancellationToken ct)
    {
        // Validate the JWT structurally and cryptographically
        var principal = await _tokenFactory.ValidateAccessTokenAsync(token, ct);
        if (principal is null) return null;

        var jti = principal.FindFirstValue("jti");
        if (jti is null) return null;

        // Cross-reference the store to detect revoked tokens
        var stored = jti is not null ? await _accessTokenStore.FindAsync(jti, ct) : null;
        if (stored is null) return null;

        // RFC 7662 §2.2: only the resource server / protected resource may introspect;
        // here we allow any authenticated client (simplification for Phase 2).
        var scopeClaim = principal.FindFirstValue("scope") ?? string.Empty;

        return Results.Json(new
        {
            active = true,
            token_type = "Bearer",
            scope = scopeClaim,
            client_id = principal.FindFirstValue("client_id"),
            sub = principal.FindFirstValue("sub"),
            iss = _options.Value.Issuer.TrimEnd('/'),
            exp = ToUnixSeconds(stored.ExpiresAt),
            iat = ToUnixSeconds(stored.ExpiresAt.AddSeconds(-_options.Value.AccessTokenLifetimeSeconds)),
            jti,
        });
    }

    private async Task<IResult?> IntrospectRefreshTokenAsync(
        string token, Client caller, CancellationToken ct)
    {
        var stored = await _refreshTokenStore.FindAsync(token, ct);
        if (stored is null) return null;

        // Callers may only introspect their own tokens
        if (stored.ClientId != caller.ClientId) return null;

        return Results.Json(new
        {
            active = true,
            token_type = "refresh_token",
            scope = string.Join(" ", stored.Scopes),
            client_id = stored.ClientId,
            sub = stored.Subject,
            iss = _options.Value.Issuer.TrimEnd('/'),
            exp = ToUnixSeconds(stored.ExpiresAt),
        });
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static IResult Inactive() => Results.Json(new { active = false });

    private static IResult Error(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);

    private static long ToUnixSeconds(DateTimeOffset dt) => dt.ToUnixTimeSeconds();
}
