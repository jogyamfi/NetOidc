using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Authorization;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Token;

/// <summary>
/// Handles the token endpoint: dispatches <c>authorization_code</c> and
/// <c>refresh_token</c> grant types.
/// </summary>
public sealed class TokenEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly IAdapter<AuthorizationCode> _codeStore;
    private readonly IAdapter<RefreshToken> _refreshTokenStore;
    private readonly IAdapter<AccessToken> _accessTokenStore;
    private readonly TokenFactory _tokenFactory;

    public TokenEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        IAdapter<AuthorizationCode> codeStore,
        IAdapter<RefreshToken> refreshTokenStore,
        IAdapter<AccessToken> accessTokenStore,
        TokenFactory tokenFactory)
    {
        _options = options;
        _clientStore = clientStore;
        _codeStore = codeStore;
        _refreshTokenStore = refreshTokenStore;
        _accessTokenStore = accessTokenStore;
        _tokenFactory = tokenFactory;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        if (!context.Request.HasFormContentType)
            return TokenError(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var client = await ClientAuthenticator.AuthenticateAsync(context, form, _clientStore, ct);
        if (client is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return TokenError(OAuthError.InvalidClient(), 401);
        }

        var grantType = form["grant_type"].ToString();
        return grantType switch
        {
            "authorization_code" => await HandleAuthorizationCodeAsync(form, client, ct),
            "refresh_token" => await HandleRefreshTokenAsync(form, client, ct),
            _ => TokenError(OAuthError.UnsupportedGrantType(), 400),
        };
    }

    // ── authorization_code grant ───────────────────────────────────────────────

    private async Task<IResult> HandleAuthorizationCodeAsync(
        IFormCollection form, Client client, CancellationToken ct)
    {
        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        if (string.IsNullOrEmpty(code))
            return TokenError(OAuthError.InvalidRequest("code is required"), 400);

        var authCode = await _codeStore.ConsumeAsync(code, ct);
        if (authCode is null)
            return TokenError(OAuthError.InvalidGrant("authorization code not found or already used"), 400);

        if (authCode.ClientId != client.ClientId)
            return TokenError(OAuthError.InvalidGrant("client_id mismatch"), 400);

        if (authCode.ExpiresAt < DateTimeOffset.UtcNow)
            return TokenError(OAuthError.InvalidGrant("authorization code expired"), 400);

        // redirect_uri must match if it was specified in the auth request
        if (!string.IsNullOrEmpty(redirectUri) && authCode.RedirectUri != redirectUri)
            return TokenError(OAuthError.InvalidGrant("redirect_uri mismatch"), 400);

        // PKCE validation
        if (authCode.CodeChallenge is not null)
        {
            if (string.IsNullOrEmpty(codeVerifier))
                return TokenError(OAuthError.InvalidRequest("code_verifier is required"), 400);
            if (!PkceValidator.Validate(codeVerifier, authCode.CodeChallenge,
                    authCode.CodeChallengeMethod ?? "plain"))
                return TokenError(OAuthError.InvalidGrant("code_verifier does not match code_challenge"), 400);
        }

        var opts = _options.Value;
        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            tokenId, authCode.Subject, client.ClientId, authCode.Scopes);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = client.ClientId,
            Subject = authCode.Subject,
            Scopes = authCode.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        string? refreshTokenValue = null;
        if (opts.IssueRefreshTokens)
        {
            refreshTokenValue = GenerateId();
            var rt = new RefreshToken
            {
                TokenId = refreshTokenValue,
                ClientId = client.ClientId,
                Subject = authCode.Subject,
                Scopes = authCode.Scopes,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.RefreshTokenLifetimeSeconds),
            };
            await _refreshTokenStore.StoreAsync(refreshTokenValue, rt,
                TimeSpan.FromSeconds(opts.RefreshTokenLifetimeSeconds), ct);
        }

        string? idToken = null;
        if (authCode.Scopes.Contains("openid"))
            idToken = _tokenFactory.CreateIdToken(
                authCode.Subject, client.ClientId, authCode.Nonce, authCode.AuthTime);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, refreshTokenValue, idToken);
    }

    // ── refresh_token grant ────────────────────────────────────────────────────

    private async Task<IResult> HandleRefreshTokenAsync(
        IFormCollection form, Client client, CancellationToken ct)
    {
        var rtValue = form["refresh_token"].ToString();
        if (string.IsNullOrEmpty(rtValue))
            return TokenError(OAuthError.InvalidRequest("refresh_token is required"), 400);

        var rt = await _refreshTokenStore.ConsumeAsync(rtValue, ct);
        if (rt is null)
            return TokenError(OAuthError.InvalidGrant("refresh token not found or already used"), 400);

        if (rt.ClientId != client.ClientId)
            return TokenError(OAuthError.InvalidGrant("client_id mismatch"), 400);

        if (rt.ExpiresAt < DateTimeOffset.UtcNow)
            return TokenError(OAuthError.InvalidGrant("refresh token expired"), 400);

        var opts = _options.Value;
        var newTokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            newTokenId, rt.Subject, client.ClientId, rt.Scopes);

        var at = new AccessToken
        {
            TokenId = newTokenId,
            GrantId = newTokenId,
            ClientId = client.ClientId,
            Subject = rt.Subject,
            Scopes = rt.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
        };
        await _accessTokenStore.StoreAsync(newTokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        // Rotate the refresh token
        var newRtId = GenerateId();
        var newRt = new RefreshToken
        {
            TokenId = newRtId,
            ClientId = client.ClientId,
            Subject = rt.Subject,
            Scopes = rt.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.RefreshTokenLifetimeSeconds),
        };
        await _refreshTokenStore.StoreAsync(newRtId, newRt,
            TimeSpan.FromSeconds(opts.RefreshTokenLifetimeSeconds), ct);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, newRtId, idToken: null);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static IResult TokenSuccess(
        string accessToken, int expiresIn, string? refreshToken, string? idToken)
    {
        var body = new Dictionary<string, object>
        {
            ["access_token"] = accessToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = expiresIn,
        };
        if (refreshToken is not null) body["refresh_token"] = refreshToken;
        if (idToken is not null) body["id_token"] = idToken;
        return Results.Json(body, statusCode: 200);
    }

    private static IResult TokenError(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);

    private static string GenerateId() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
