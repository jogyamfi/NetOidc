using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Events;
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
    private readonly RefreshTokenService _refreshTokens;
    private readonly TokenFactory _tokenFactory;
    private readonly IOptions<ProviderOptions> _options;
    private readonly IProviderEventSink _events;

    public IntrospectionEndpointHandler(
        IClientStore clientStore,
        IAdapter<AccessToken> accessTokenStore,
        RefreshTokenService refreshTokens,
        TokenFactory tokenFactory,
        IOptions<ProviderOptions> options,
        IProviderEventSink events)
    {
        _clientStore = clientStore;
        _accessTokenStore = accessTokenStore;
        _refreshTokens = refreshTokens;
        _tokenFactory = tokenFactory;
        _options = options;
        _events = events;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        if (!context.Request.HasFormContentType)
            return Error(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var caller = await ClientAuthenticator.AuthenticateAsync(
            context, form, _clientStore, _options.Value, ct);
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
        IResult? result;
        if (hint == "refresh_token")
            result = await IntrospectRefreshTokenAsync(token, caller, ct)
                     ?? await IntrospectAccessTokenAsync(token, caller, ct);
        else
            result = await IntrospectAccessTokenAsync(token, caller, ct)
                     ?? await IntrospectRefreshTokenAsync(token, caller, ct);

        await _events.TokenIntrospectedAsync(new TokenIntrospectedEvent(
            caller.ClientId, Active: result is not null, TokenSubject: null, DateTimeOffset.UtcNow), ct);

        return result ?? Inactive();
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
        var stored = await _accessTokenStore.FindAsync(jti, ct);
        if (stored is null) return null;

        // RFC 7662 §4: don't disclose token metadata to arbitrary clients. By default a caller
        // may introspect tokens issued to it or intended for it (aud); resource servers are
        // authorised through the AuthorizeIntrospection hook. Unauthorised → inactive.
        var audiences = principal.FindAll("aud").Select(c => c.Value).ToList();
        var opts = _options.Value;
        var permitted = stored.ClientId == caller.ClientId || audiences.Contains(caller.ClientId);
        if (!permitted && opts.AuthorizeIntrospection is not null)
            permitted = await opts.AuthorizeIntrospection(
                new IntrospectionContext(caller.ClientId, stored.ClientId, stored.Subject, audiences, stored.Scopes), ct);
        if (!permitted) return null;

        var body = new Dictionary<string, object?>
        {
            ["active"] = true,
            ["token_type"] = stored.CnfJwkThumbprint is not null ? "DPoP" : "Bearer",
            ["scope"] = principal.FindFirstValue("scope") ?? string.Empty,
            ["client_id"] = stored.ClientId,
            ["iss"] = opts.Issuer.TrimEnd('/'),
            ["exp"] = ToUnixSeconds(stored.ExpiresAt),
            ["jti"] = jti,
        };
        if (stored.Subject is not null) body["sub"] = stored.Subject;
        if (long.TryParse(principal.FindFirstValue("iat"), out var iat)) body["iat"] = iat;
        if (audiences.Count > 0) body["aud"] = audiences.Count == 1 ? audiences[0] : audiences;

        // RFC 9449 §6.2 / RFC 8705 §3.2: expose the confirmation so resource servers can enforce it.
        if (stored.CnfJwkThumbprint is not null)
            body["cnf"] = new Dictionary<string, string> { ["jkt"] = stored.CnfJwkThumbprint };
        else if (stored.CnfX5tS256 is not null)
            body["cnf"] = new Dictionary<string, string> { ["x5t#S256"] = stored.CnfX5tS256 };

        return Results.Json(body);
    }

    private async Task<IResult?> IntrospectRefreshTokenAsync(
        string token, Client caller, CancellationToken ct)
    {
        // Rotated, expired and family-revoked tokens are inactive.
        var stored = await _refreshTokens.FindActiveAsync(token, ct);
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
