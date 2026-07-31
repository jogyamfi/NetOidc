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
/// Handles the token endpoint: dispatches authorization_code, refresh_token,
/// client_credentials, token-exchange (RFC 8693), and jwt-bearer (RFC 7523) grant types.
/// </summary>
public sealed class TokenEndpointHandler
{
    // Token type URIs (RFC 8693 §3)
    private const string TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";
    private const string TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";
    private const string TokenTypeIdToken = "urn:ietf:params:oauth:token-type:id_token";

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
            "client_credentials" => await HandleClientCredentialsAsync(form, client, ct),
            "urn:ietf:params:oauth:grant-type:token-exchange"
                when _options.Value.TokenExchangeEnabled
                => await HandleTokenExchangeAsync(form, client, ct),
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
                when _options.Value.JwtBearerGrantEnabled
                => await HandleJwtBearerAsync(form, client, ct),
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
            Resource = authCode.Resources.Count > 0 ? authCode.Resources[0] : null,
            AuthorizationDetailsJson = authCode.AuthorizationDetailsJson,
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
                Resources = authCode.Resources,
                AuthorizationDetailsJson = authCode.AuthorizationDetailsJson,
            };
            await _refreshTokenStore.StoreAsync(refreshTokenValue, rt,
                TimeSpan.FromSeconds(opts.RefreshTokenLifetimeSeconds), ct);
        }

        string? idToken = null;
        if (authCode.Scopes.Contains("openid"))
            idToken = _tokenFactory.CreateIdToken(
                authCode.Subject, client.ClientId, authCode.Nonce, authCode.AuthTime,
                acr: authCode.Acr, amr: authCode.Amr, sid: authCode.SessionId);

        var body = BuildTokenBody(atValue, opts.AccessTokenLifetimeSeconds, refreshTokenValue, idToken);
        if (authCode.AuthorizationDetailsJson is not null)
            body["authorization_details"] = System.Text.Json.JsonSerializer
                .Deserialize<object>(authCode.AuthorizationDetailsJson)!;
        return Results.Json(body, statusCode: 200);
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

        var newAt = new AccessToken
        {
            TokenId = newTokenId,
            GrantId = newTokenId,
            ClientId = client.ClientId,
            Subject = rt.Subject,
            Scopes = rt.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            Resource = rt.Resources.Count > 0 ? rt.Resources[0] : null,
            AuthorizationDetailsJson = rt.AuthorizationDetailsJson,
        };
        await _accessTokenStore.StoreAsync(newTokenId, newAt,
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
            Resources = rt.Resources,
            AuthorizationDetailsJson = rt.AuthorizationDetailsJson,
        };
        await _refreshTokenStore.StoreAsync(newRtId, newRt,
            TimeSpan.FromSeconds(opts.RefreshTokenLifetimeSeconds), ct);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, newRtId, idToken: null);
    }

    // ── client_credentials grant ───────────────────────────────────────────────

    private async Task<IResult> HandleClientCredentialsAsync(
        IFormCollection form, Client client, CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains("client_credentials"))
            return TokenError(OAuthError.UnauthorizedClient("client_credentials not allowed for this client"), 400);

        var scopeStr = form["scope"].ToString();
        var requestedScopes = string.IsNullOrEmpty(scopeStr)
            ? client.AllowedScopes.ToList()
            : scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        var registeredScopes = _options.Value.Scopes.Select(s => s.Name).ToHashSet();
        var unknownScopes = requestedScopes.Where(s => !registeredScopes.Contains(s)).ToList();
        if (unknownScopes.Count > 0)
            return TokenError(OAuthError.InvalidScope($"Unknown scope(s): {string.Join(" ", unknownScopes)}"), 400);

        var disallowedScopes = requestedScopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
        if (disallowedScopes.Count > 0)
            return TokenError(OAuthError.InvalidScope($"Client not authorized for scope(s): {string.Join(" ", disallowedScopes)}"), 400);

        var opts = _options.Value;
        var tokenId = GenerateId();
        // client_credentials has no resource-owner subject (RFC 6749 §4.4)
        var atValue = _tokenFactory.CreateAccessToken(tokenId, subject: null, client.ClientId, requestedScopes);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = client.ClientId,
            Subject = null,
            Scopes = requestedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, refreshToken: null, idToken: null);
    }

    // ── token-exchange grant (RFC 8693) ───────────────────────────────────────

    private async Task<IResult> HandleTokenExchangeAsync(
        IFormCollection form, Client client, CancellationToken ct)
    {
        var subjectToken = form["subject_token"].ToString();
        var subjectTokenType = form["subject_token_type"].ToString();

        if (string.IsNullOrEmpty(subjectToken))
            return TokenError(OAuthError.InvalidRequest("subject_token is required"), 400);
        if (string.IsNullOrEmpty(subjectTokenType))
            return TokenError(OAuthError.InvalidRequest("subject_token_type is required"), 400);

        // Validate the subject token and extract the subject
        string? subject = null;
        IReadOnlyList<string> scopes;

        switch (subjectTokenType)
        {
            case TokenTypeAccessToken:
            {
                var at = await _accessTokenStore.FindAsync(subjectToken, ct);
                if (at is null || at.ExpiresAt < DateTimeOffset.UtcNow)
                {
                    // Try validating as JWT AT
                    var principal = await _tokenFactory.ValidateAccessTokenAsync(subjectToken, ct);
                    if (principal is null)
                        return TokenError(OAuthError.InvalidGrant("subject_token is invalid or expired"), 400);
                    subject = principal.FindFirst("sub")?.Value;
                    scopes = (principal.FindFirst("scope")?.Value ?? string.Empty)
                        .Split(' ', StringSplitOptions.RemoveEmptyEntries);
                }
                else
                {
                    subject = at.Subject;
                    scopes = at.Scopes;
                }
                break;
            }
            case TokenTypeRefreshToken:
            {
                var rt = await _refreshTokenStore.FindAsync(subjectToken, ct);
                if (rt is null || rt.ExpiresAt < DateTimeOffset.UtcNow)
                    return TokenError(OAuthError.InvalidGrant("subject_token is invalid or expired"), 400);
                subject = rt.Subject;
                scopes = rt.Scopes;
                break;
            }
            case TokenTypeIdToken:
            {
                var principal = await _tokenFactory.ValidateIdTokenHintAsync(subjectToken, ct);
                if (principal is null)
                    return TokenError(OAuthError.InvalidGrant("subject_token (id_token) is invalid"), 400);
                subject = principal.FindFirst("sub")?.Value;
                scopes = [];
                break;
            }
            default:
                return TokenError(OAuthError.InvalidTokenType(
                    $"Unsupported subject_token_type: {subjectTokenType}"), 400);
        }

        // Requested scope (optional — default to subject token scopes)
        var scopeStr = form["scope"].ToString();
        var requestedScopes = string.IsNullOrEmpty(scopeStr)
            ? scopes.ToList()
            : scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        var opts = _options.Value;
        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(tokenId, subject, client.ClientId, requestedScopes);

        var newAt = new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = client.ClientId,
            Subject = subject,
            Scopes = requestedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
        };
        await _accessTokenStore.StoreAsync(tokenId, newAt,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        var body = BuildTokenBody(atValue, opts.AccessTokenLifetimeSeconds, null, null);
        body["issued_token_type"] = TokenTypeAccessToken;
        return Results.Json(body, statusCode: 200);
    }

    // ── jwt-bearer grant (RFC 7523) ────────────────────────────────────────────

    private async Task<IResult> HandleJwtBearerAsync(
        IFormCollection form, Client client, CancellationToken ct)
    {
        var assertion = form["assertion"].ToString();
        if (string.IsNullOrEmpty(assertion))
            return TokenError(OAuthError.InvalidRequest("assertion is required"), 400);

        if (string.IsNullOrEmpty(client.JwksJson))
            return TokenError(OAuthError.InvalidClient(
                "client has no JWKS configured; cannot verify JWT assertion"), 401);

        Microsoft.IdentityModel.Tokens.JsonWebKeySet jwks;
        try { jwks = new Microsoft.IdentityModel.Tokens.JsonWebKeySet(client.JwksJson); }
        catch { return TokenError(OAuthError.InvalidClient("client JWKS is malformed"), 401); }

        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        var opts = _options.Value;

        var result = await handler.ValidateTokenAsync(assertion,
            new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidIssuer = client.ClientId,
                ValidAudience = opts.Issuer.TrimEnd('/'),
                IssuerSigningKeys = jwks.GetSigningKeys(),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
            });

        if (!result.IsValid)
            return TokenError(OAuthError.InvalidGrant(
                result.Exception?.Message ?? "JWT assertion validation failed"), 400);

        var subject = result.Claims.TryGetValue("sub", out var subVal)
            ? subVal?.ToString()
            : null;

        var scopeStr = form["scope"].ToString();
        var requestedScopes = string.IsNullOrEmpty(scopeStr)
            ? client.AllowedScopes.ToList()
            : scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        var registeredScopes = opts.Scopes.Select(s => s.Name).ToHashSet();
        var unknownScopes = requestedScopes.Where(s => !registeredScopes.Contains(s)).ToList();
        if (unknownScopes.Count > 0)
            return TokenError(OAuthError.InvalidScope($"Unknown scope(s): {string.Join(" ", unknownScopes)}"), 400);

        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(tokenId, subject, client.ClientId, requestedScopes);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = client.ClientId,
            Subject = subject,
            Scopes = requestedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, null, null);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static IResult TokenSuccess(
        string accessToken, int expiresIn, string? refreshToken, string? idToken)
    {
        var body = BuildTokenBody(accessToken, expiresIn, refreshToken, idToken);
        return Results.Json(body, statusCode: 200);
    }

    private static Dictionary<string, object> BuildTokenBody(
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
        return body;
    }

    private static IResult TokenError(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);

    private static string GenerateId() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
