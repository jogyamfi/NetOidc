using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Token;

/// <summary>
/// Handles the token revocation endpoint (RFC 7009).
/// Always responds with 200 OK regardless of whether the token was found,
/// per the "no information about the token" requirement of the spec.
/// </summary>
public sealed class RevocationEndpointHandler
{
    private readonly IClientStore _clientStore;
    private readonly IAdapter<AccessToken> _accessTokenStore;
    private readonly IAdapter<RefreshToken> _refreshTokenStore;
    private readonly TokenFactory _tokenFactory;
    private readonly IOptions<ProviderOptions> _options;

    public RevocationEndpointHandler(
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
            return Results.Json(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"),
                statusCode: 400);

        var form = await context.Request.ReadFormAsync(ct);

        var caller = await ClientAuthenticator.AuthenticateAsync(
            context, form, _clientStore, _options.Value, ct);
        if (caller is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return Results.Json(OAuthError.InvalidClient(), statusCode: 401);
        }

        var token = form["token"].ToString();
        if (string.IsNullOrEmpty(token))
            return Results.Ok(); // RFC 7009: missing token → 200, treat as no-op

        var hint = form["token_type_hint"].ToString();

        if (hint == "refresh_token")
        {
            await TryRevokeRefreshTokenAsync(token, caller, ct);
            await TryRevokeAccessTokenAsync(token, caller, ct);
        }
        else
        {
            // Default: try access_token first, then refresh_token
            await TryRevokeAccessTokenAsync(token, caller, ct);
            await TryRevokeRefreshTokenAsync(token, caller, ct);
        }

        // RFC 7009 §2.2: response is always 200 OK with an empty body
        return Results.Ok();
    }

    // ── Per-type revocation ────────────────────────────────────────────────────

    private async Task TryRevokeAccessTokenAsync(string token, Client caller, CancellationToken ct)
    {
        // JWT access tokens: validate to extract jti, then remove from store
        var principal = await _tokenFactory.ValidateAccessTokenAsync(token, ct);
        if (principal is null) return;

        var jti = principal.FindFirstValue("jti");
        if (jti is null) return;

        var stored = await _accessTokenStore.FindAsync(jti, ct);
        if (stored is null) return;

        // Clients may only revoke their own tokens
        if (stored.ClientId != caller.ClientId) return;

        await _accessTokenStore.RemoveAsync(jti, ct);
    }

    private async Task TryRevokeRefreshTokenAsync(string token, Client caller, CancellationToken ct)
    {
        var stored = await _refreshTokenStore.FindAsync(token, ct);
        if (stored is null) return;

        if (stored.ClientId != caller.ClientId) return;

        await _refreshTokenStore.RemoveAsync(token, ct);
    }
}
