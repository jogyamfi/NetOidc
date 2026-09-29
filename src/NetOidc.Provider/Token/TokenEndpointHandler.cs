using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Authorization;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.DPoP;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Token;

/// <summary>
/// Handles the token endpoint: dispatches authorization_code, refresh_token,
/// client_credentials, token-exchange (RFC 8693), jwt-bearer (RFC 7523),
/// device_code (RFC 8628), and CIBA grant types.
/// Phase 5: DPoP proof validation and mTLS certificate binding.
/// Phase 6: device_code and CIBA poll grants.
/// </summary>
public sealed class TokenEndpointHandler
{
    // Token type URIs (RFC 8693 §3)
    private const string TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";
    private const string TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";
    private const string TokenTypeIdToken = "urn:ietf:params:oauth:token-type:id_token";

    private const string GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string GrantTypeJwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private readonly IOptions<ProviderOptions> _options;
    private readonly ClientAuthenticator _clientAuthenticator;
    private readonly IAdapter<AuthorizationCode> _codeStore;
    private readonly RefreshTokenService _refreshTokens;
    private readonly IAdapter<AccessToken> _accessTokenStore;
    private readonly IAdapter<DeviceCode> _deviceCodeStore;
    private readonly IAdapter<BackchannelAuthenticationRequest> _cibaStore;
    private readonly TokenFactory _tokenFactory;
    private readonly DPopProofValidator _dpopValidator;
    private readonly IProviderEventSink _events;
    private readonly IReplayCache _replayCache;
    private readonly AccessTokenService _accessTokens;
    private readonly ILogger<TokenEndpointHandler> _logger;

    public TokenEndpointHandler(
        IOptions<ProviderOptions> options,
        ClientAuthenticator clientAuthenticator,
        IAdapter<AuthorizationCode> codeStore,
        RefreshTokenService refreshTokens,
        IAdapter<AccessToken> accessTokenStore,
        IAdapter<DeviceCode> deviceCodeStore,
        IAdapter<BackchannelAuthenticationRequest> cibaStore,
        TokenFactory tokenFactory,
        DPopProofValidator dpopValidator,
        IProviderEventSink events,
        IReplayCache replayCache,
        AccessTokenService accessTokens,
        ILogger<TokenEndpointHandler> logger)
    {
        _logger = logger;
        _replayCache = replayCache;
        _accessTokens = accessTokens;
        _options = options;
        _clientAuthenticator = clientAuthenticator;
        _codeStore = codeStore;
        _refreshTokens = refreshTokens;
        _accessTokenStore = accessTokenStore;
        _deviceCodeStore = deviceCodeStore;
        _cibaStore = cibaStore;
        _tokenFactory = tokenFactory;
        _dpopValidator = dpopValidator;
        _events = events;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        if (!context.Request.HasFormContentType)
            return TokenError(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);
        var opts = _options.Value;

        var client = await _clientAuthenticator.AuthenticateAsync(context, form, ct);
        if (client is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return TokenError(OAuthError.InvalidClient(), 401);
        }

        // ── DPoP proof validation (RFC 9449) ────────────────────────────────────
        string? cnfJwkThumbprint = null;
        var dpopHeader = context.Request.Headers["DPoP"].ToString();
        if (!string.IsNullOrEmpty(dpopHeader))
        {
            if (!opts.DPoPEnabled)
                return TokenError(OAuthError.InvalidRequest("DPoP is not supported by this server"), 400);

            var tokenEndpointUri = opts.Issuer.TrimEnd('/') + opts.TokenEndpoint;
            cnfJwkThumbprint = await _dpopValidator.ValidateProofAsync(
                dpopHeader,
                context.Request.Method,
                tokenEndpointUri,
                accessToken: null,
                clockSkewSeconds: opts.DPoPProofLifetimeSeconds);

            if (cnfJwkThumbprint is null)
                return TokenError(OAuthError.InvalidDPoPProof("DPoP proof is missing or invalid"), 400);
        }

        // ── mTLS certificate binding (RFC 8705 §3) ──────────────────────────────
        string? cnfX5tS256 = null;
        if (opts.MtlsEnabled && client.UseMtlsBoundTokens)
        {
            var cert = _clientAuthenticator.GetClientCertificate(context);
            if (cert is not null)
                cnfX5tS256 = ClientAuthenticator.ComputeCertThumbprint(cert);
        }

        var grantType = form["grant_type"].ToString();
        return grantType switch
        {
            "authorization_code" => await HandleAuthorizationCodeAsync(
                form, client, cnfJwkThumbprint, cnfX5tS256, ct),
            "refresh_token" => await HandleRefreshTokenAsync(
                form, client, cnfJwkThumbprint, cnfX5tS256, ct),
            "client_credentials" => await HandleClientCredentialsAsync(
                form, client, cnfJwkThumbprint, cnfX5tS256, ct),
            "urn:ietf:params:oauth:grant-type:token-exchange"
                when opts.TokenExchangeEnabled
                => await HandleTokenExchangeAsync(form, client, cnfJwkThumbprint, cnfX5tS256, ct),
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
                when opts.JwtBearerGrantEnabled
                => await HandleJwtBearerAsync(form, client, cnfJwkThumbprint, cnfX5tS256, ct),
            "urn:ietf:params:oauth:grant-type:device_code"
                when opts.DeviceFlowEnabled
                => await HandleDeviceCodeAsync(form, client, cnfJwkThumbprint, cnfX5tS256, ct),
            "urn:ietf:params:oauth:grant-type:ciba"
                when opts.CibaEnabled
                => await HandleCibaAsync(form, client, cnfJwkThumbprint, cnfX5tS256, ct),
            _ => TokenError(OAuthError.UnsupportedGrantType(), 400),
        };
    }

    // ── authorization_code grant ───────────────────────────────────────────────

    private async Task<IResult> HandleAuthorizationCodeAsync(
        IFormCollection form, Client client,
        string? cnfJwkThumbprint, string? cnfX5tS256,
        CancellationToken ct)
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

        // RFC 6749 §4.1.3: if redirect_uri was in the authorization request it must be
        // repeated here, identically; a supplied value must always match.
        if (authCode.RedirectUriInRequest && string.IsNullOrEmpty(redirectUri))
            return TokenError(OAuthError.InvalidGrant("redirect_uri is required"), 400);
        if (!string.IsNullOrEmpty(redirectUri) && !string.Equals(authCode.RedirectUri, redirectUri, StringComparison.Ordinal))
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

        // Issue the refresh token first so the access token joins its grant (revocation cascade).
        var refresh = opts.IssueRefreshTokens
            ? await _refreshTokens.IssueAsync(
                client, authCode.Subject, authCode.Scopes, authCode.Resources,
                authCode.AuthorizationDetailsJson, cnfJwkThumbprint, cnfX5tS256, ct)
            : null;
        var refreshTokenValue = refresh?.Value;

        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            tokenId, authCode.Subject, client.ClientId, authCode.Scopes,
            cnfJwkThumbprint, cnfX5tS256);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = refresh?.GrantId ?? tokenId,
            ClientId = client.ClientId,
            Subject = authCode.Subject,
            Scopes = authCode.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            Resource = authCode.Resources.Count > 0 ? authCode.Resources[0] : null,
            AuthorizationDetailsJson = authCode.AuthorizationDetailsJson,
            CnfJwkThumbprint = cnfJwkThumbprint,
            CnfX5tS256 = cnfX5tS256,
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        string? idToken = null;
        if (authCode.Scopes.Contains("openid"))
            idToken = _tokenFactory.CreateIdToken(
                authCode.Subject, client.ClientId, authCode.Nonce, authCode.AuthTime,
                acr: authCode.Acr, amr: authCode.Amr, sid: authCode.SessionId);

        var body = BuildTokenBody(atValue, opts.AccessTokenLifetimeSeconds, refreshTokenValue, idToken,
            tokenType: cnfJwkThumbprint is not null ? "DPoP" : "Bearer");
        if (authCode.AuthorizationDetailsJson is not null)
            body["authorization_details"] = System.Text.Json.JsonSerializer
                .Deserialize<object>(authCode.AuthorizationDetailsJson)!;

        await _events.TokenIssuedAsync(new TokenIssuedEvent(
            client.ClientId, authCode.Subject, "authorization_code",
            authCode.Scopes, DateTimeOffset.UtcNow), ct);

        return Results.Json(body, statusCode: 200);
    }

    // ── refresh_token grant ────────────────────────────────────────────────────

    private async Task<IResult> HandleRefreshTokenAsync(
        IFormCollection form, Client client,
        string? cnfJwkThumbprint, string? cnfX5tS256,
        CancellationToken ct)
    {
        var rtValue = form["refresh_token"].ToString();
        if (string.IsNullOrEmpty(rtValue))
            return TokenError(OAuthError.InvalidRequest("refresh_token is required"), 400);

        var rotation = await _refreshTokens.RotateAsync(rtValue, client, cnfJwkThumbprint, cnfX5tS256, ct);
        if (!rotation.Succeeded)
            return TokenError(OAuthError.InvalidGrant(rotation.Error), 400);
        var rt = rotation.Token!;

        var opts = _options.Value;

        // Keep the family; a bound token stays bound to the key it was issued for.
        var successor = await _refreshTokens.IssueSuccessorAsync(client, rt, ct);

        var newTokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            newTokenId, rt.Subject, client.ClientId, rt.Scopes,
            cnfJwkThumbprint, cnfX5tS256);

        var newAt = new AccessToken
        {
            TokenId = newTokenId,
            GrantId = successor.GrantId,
            ClientId = client.ClientId,
            Subject = rt.Subject,
            Scopes = rt.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            Resource = rt.Resources.Count > 0 ? rt.Resources[0] : null,
            AuthorizationDetailsJson = rt.AuthorizationDetailsJson,
            CnfJwkThumbprint = cnfJwkThumbprint,
            CnfX5tS256 = cnfX5tS256,
        };
        await _accessTokenStore.StoreAsync(newTokenId, newAt,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        await _events.TokenIssuedAsync(new TokenIssuedEvent(
            client.ClientId, rt.Subject, "refresh_token",
            rt.Scopes, DateTimeOffset.UtcNow), ct);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, successor.Value, idToken: null,
            tokenType: cnfJwkThumbprint is not null ? "DPoP" : "Bearer");
    }

    // ── client_credentials grant ───────────────────────────────────────────────

    private async Task<IResult> HandleClientCredentialsAsync(
        IFormCollection form, Client client,
        string? cnfJwkThumbprint, string? cnfX5tS256,
        CancellationToken ct)
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
        var atValue = _tokenFactory.CreateAccessToken(
            tokenId, subject: null, client.ClientId, requestedScopes,
            cnfJwkThumbprint, cnfX5tS256);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = client.ClientId,
            Subject = null,
            Scopes = requestedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            CnfJwkThumbprint = cnfJwkThumbprint,
            CnfX5tS256 = cnfX5tS256,
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        await _events.TokenIssuedAsync(new TokenIssuedEvent(
            client.ClientId, Subject: null, "client_credentials",
            requestedScopes, DateTimeOffset.UtcNow), ct);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, refreshToken: null, idToken: null,
            tokenType: cnfJwkThumbprint is not null ? "DPoP" : "Bearer");
    }

    // ── token-exchange grant (RFC 8693) ───────────────────────────────────────

    private async Task<IResult> HandleTokenExchangeAsync(
        IFormCollection form, Client client,
        string? cnfJwkThumbprint, string? cnfX5tS256,
        CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains(GrantTypeTokenExchange))
            return TokenError(OAuthError.UnauthorizedClient("token-exchange not allowed for this client"), 400);

        var subjectToken = form["subject_token"].ToString();
        var subjectTokenType = form["subject_token_type"].ToString();

        if (string.IsNullOrEmpty(subjectToken))
            return TokenError(OAuthError.InvalidRequest("subject_token is required"), 400);
        if (string.IsNullOrEmpty(subjectTokenType))
            return TokenError(OAuthError.InvalidRequest("subject_token_type is required"), 400);

        // Delegation (actor_token) is not implemented; refuse rather than silently ignore it.
        if (!string.IsNullOrEmpty(form["actor_token"].ToString()))
            return TokenError(OAuthError.InvalidRequest("actor_token is not supported"), 400);

        string? subject;
        string subjectClientId;
        IReadOnlyList<string> subjectScopes;

        switch (subjectTokenType)
        {
            case TokenTypeAccessToken:
            {
                // Signature, lifetime, revocation and grant liveness.
                var live = await _accessTokens.ValidateAsync(subjectToken, ct);
                if (live is null)
                    return TokenError(OAuthError.InvalidGrant("subject_token is invalid, expired or revoked"), 400);
                var at = live.Record;
                subject = at.Subject;
                subjectClientId = at.ClientId;
                subjectScopes = at.Scopes;
                break;
            }
            case TokenTypeRefreshToken:
            {
                var rt = await _refreshTokens.FindActiveAsync(subjectToken, ct);
                if (rt is null)
                    return TokenError(OAuthError.InvalidGrant("subject_token is invalid, expired or revoked"), 400);
                subject = rt.Subject;
                subjectClientId = rt.ClientId;
                subjectScopes = rt.Scopes;
                break;
            }
            case TokenTypeIdToken:
            {
                var principal = await _tokenFactory.ValidateIdTokenAsync(subjectToken, ct);
                var aud = principal?.FindFirst("azp")?.Value ?? principal?.FindFirst("aud")?.Value;
                if (principal is null || aud is null)
                    return TokenError(OAuthError.InvalidGrant("subject_token (id_token) is invalid or expired"), 400);
                subject = principal.FindFirst("sub")?.Value;
                subjectClientId = aud;
                subjectScopes = ["openid"];
                break;
            }
            default:
                return TokenError(OAuthError.InvalidTokenType(
                    $"Unsupported subject_token_type: {subjectTokenType}"), 400);
        }

        // The new token can never carry more than the subject token and the client allow.
        var ceiling = subjectScopes.Where(client.AllowedScopes.Contains).ToList();
        var scopeStr = form["scope"].ToString();
        List<string> requestedScopes;
        if (string.IsNullOrEmpty(scopeStr))
        {
            requestedScopes = ceiling;
        }
        else
        {
            requestedScopes = scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();
            var excess = requestedScopes.Where(s => !ceiling.Contains(s)).ToList();
            if (excess.Count > 0)
                return TokenError(OAuthError.InvalidScope(
                    $"Scope(s) exceed the subject token or client grant: {string.Join(" ", excess)}"), 400);
        }

        var opts = _options.Value;
        var exchange = new TokenExchangeContext(
            client.ClientId, subjectClientId, subject, subjectTokenType,
            subjectScopes, requestedScopes,
            form["audience"].Where(a => !string.IsNullOrEmpty(a)).Select(a => a!).ToList(),
            form["resource"].Where(r => !string.IsNullOrEmpty(r)).Select(r => r!).ToList());

        var permitted = opts.AuthorizeTokenExchange is null
            ? subjectClientId == client.ClientId
            : await opts.AuthorizeTokenExchange(exchange, ct);
        if (!permitted)
            return TokenError(OAuthError.InvalidGrant("client is not permitted to exchange this subject_token"), 400);

        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            tokenId, subject, client.ClientId, requestedScopes,
            cnfJwkThumbprint, cnfX5tS256);

        var newAt = new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = client.ClientId,
            Subject = subject,
            Scopes = requestedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            CnfJwkThumbprint = cnfJwkThumbprint,
            CnfX5tS256 = cnfX5tS256,
        };
        await _accessTokenStore.StoreAsync(tokenId, newAt,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        var body = BuildTokenBody(atValue, opts.AccessTokenLifetimeSeconds, null, null,
            tokenType: cnfJwkThumbprint is not null ? "DPoP" : "Bearer");
        body["issued_token_type"] = TokenTypeAccessToken;
        return Results.Json(body, statusCode: 200);
    }

    // ── jwt-bearer grant (RFC 7523) ────────────────────────────────────────────

    private async Task<IResult> HandleJwtBearerAsync(
        IFormCollection form, Client client,
        string? cnfJwkThumbprint, string? cnfX5tS256,
        CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains(GrantTypeJwtBearer))
            return TokenError(OAuthError.UnauthorizedClient("jwt-bearer not allowed for this client"), 400);

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
        {
            _logger.LogInformation(result.Exception, "jwt-bearer assertion from client {ClientId} failed validation", client.ClientId);
            return TokenError(OAuthError.InvalidGrant("assertion signature, issuer, audience or lifetime is invalid"), 400);
        }

        var subject = result.Claims.TryGetValue("sub", out var subVal)
            ? subVal?.ToString()
            : null;

        // RFC 7523 §3: jti enables one-time use; require it and refuse replays.
        var jti = result.Claims.TryGetValue("jti", out var jtiVal) ? jtiVal?.ToString() : null;
        if (string.IsNullOrEmpty(jti))
            return TokenError(OAuthError.InvalidGrant("assertion must contain a jti claim"), 400);
        var assertionExpiry = result.SecurityToken.ValidTo == DateTime.MinValue
            ? DateTimeOffset.UtcNow.AddMinutes(10)
            : new DateTimeOffset(result.SecurityToken.ValidTo, TimeSpan.Zero).AddSeconds(30);
        if (!await _replayCache.TryAddAsync($"jwt-bearer:{client.ClientId}:{jti}", assertionExpiry, ct))
            return TokenError(OAuthError.InvalidGrant("assertion has already been used"), 400);

        var scopeStr = form["scope"].ToString();
        var requestedScopes = string.IsNullOrEmpty(scopeStr)
            ? client.AllowedScopes.ToList()
            : scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();

        var registeredScopes = opts.Scopes.Select(s => s.Name).ToHashSet();
        var unknownScopes = requestedScopes.Where(s => !registeredScopes.Contains(s)).ToList();
        if (unknownScopes.Count > 0)
            return TokenError(OAuthError.InvalidScope($"Unknown scope(s): {string.Join(" ", unknownScopes)}"), 400);

        var disallowedScopes = requestedScopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
        if (disallowedScopes.Count > 0)
            return TokenError(OAuthError.InvalidScope(
                $"Client not authorized for scope(s): {string.Join(" ", disallowedScopes)}"), 400);

        // Only the operator can say which subjects a client may speak for.
        var permitted = opts.AuthorizeJwtBearerSubject is not null &&
            await opts.AuthorizeJwtBearerSubject(
                new JwtBearerContext(client.ClientId, subject, requestedScopes), ct);
        if (!permitted)
            return TokenError(OAuthError.InvalidGrant("client is not permitted to assert this subject"), 400);

        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            tokenId, subject, client.ClientId, requestedScopes,
            cnfJwkThumbprint, cnfX5tS256);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = client.ClientId,
            Subject = subject,
            Scopes = requestedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            CnfJwkThumbprint = cnfJwkThumbprint,
            CnfX5tS256 = cnfX5tS256,
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, null, null,
            tokenType: cnfJwkThumbprint is not null ? "DPoP" : "Bearer");
    }

    // ── device_code grant (RFC 8628 §3.4) ────────────────────────────────────

    private async Task<IResult> HandleDeviceCodeAsync(
        IFormCollection form, Client client,
        string? cnfJwkThumbprint, string? cnfX5tS256,
        CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains("urn:ietf:params:oauth:grant-type:device_code"))
            return TokenError(OAuthError.UnauthorizedClient("device_code grant not allowed for this client"), 400);

        var deviceCodeValue = form["device_code"].ToString();
        if (string.IsNullOrEmpty(deviceCodeValue))
            return TokenError(OAuthError.InvalidRequest("device_code is required"), 400);

        var deviceCode = await _deviceCodeStore.FindAsync(deviceCodeValue, ct);
        if (deviceCode is null)
            return TokenError(OAuthError.InvalidGrant("device code not found"), 400);

        if (deviceCode.ClientId != client.ClientId)
            return TokenError(OAuthError.InvalidGrant("client_id mismatch"), 400);

        if (deviceCode.ExpiresAt <= DateTimeOffset.UtcNow)
            return TokenError(OAuthError.ExpiredToken("device code has expired"), 400);

        // Enforce minimum polling interval (RFC 8628 §3.5)
        var opts = _options.Value;
        var now = DateTimeOffset.UtcNow;
        if (deviceCode.LastPolledAt.HasValue)
        {
            var elapsed = now - deviceCode.LastPolledAt.Value;
            if (elapsed.TotalSeconds < opts.DevicePollingIntervalSeconds)
            {
                deviceCode.LastPolledAt = now;
                var remaining = deviceCode.ExpiresAt - now;
                if (remaining > TimeSpan.Zero)
                    await _deviceCodeStore.StoreAsync(deviceCodeValue, deviceCode, remaining, ct);
                return TokenError(OAuthError.SlowDown("polling too frequently"), 400);
            }
        }
        deviceCode.LastPolledAt = now;

        switch (deviceCode.Status)
        {
            case DeviceCodeStatus.Pending:
            {
                var remaining = deviceCode.ExpiresAt - now;
                if (remaining > TimeSpan.Zero)
                    await _deviceCodeStore.StoreAsync(deviceCodeValue, deviceCode, remaining, ct);
                return TokenError(OAuthError.AuthorizationPending("user has not yet authorized"), 400);
            }
            case DeviceCodeStatus.Denied:
                await _deviceCodeStore.RemoveAsync(deviceCodeValue, ct);
                return TokenError(OAuthError.AccessDenied("user denied the authorization request"), 400);
        }

        // Approved — consume atomically so concurrent polls cannot both redeem it.
        if (await _deviceCodeStore.ConsumeAsync(deviceCodeValue, ct) is null)
            return TokenError(OAuthError.InvalidGrant("device code already redeemed"), 400);

        var refresh = opts.IssueRefreshTokens
            ? await _refreshTokens.IssueAsync(
                client, deviceCode.Subject!, deviceCode.GrantedScopes, resources: [],
                authorizationDetailsJson: null, cnfJwkThumbprint, cnfX5tS256, ct)
            : null;
        var refreshTokenValue = refresh?.Value;

        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            tokenId, deviceCode.Subject!, client.ClientId, deviceCode.GrantedScopes,
            cnfJwkThumbprint, cnfX5tS256);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = refresh?.GrantId ?? tokenId,
            ClientId = client.ClientId,
            Subject = deviceCode.Subject,
            Scopes = deviceCode.GrantedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            CnfJwkThumbprint = cnfJwkThumbprint,
            CnfX5tS256 = cnfX5tS256,
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        string? idToken = null;
        if (deviceCode.GrantedScopes.Contains("openid"))
            idToken = _tokenFactory.CreateIdToken(
                deviceCode.Subject!, client.ClientId, nonce: null,
                authTime: deviceCode.CreatedAt,
                acr: null, amr: null, sid: null);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, refreshTokenValue, idToken,
            tokenType: cnfJwkThumbprint is not null ? "DPoP" : "Bearer");
    }

    // ── CIBA poll grant (OpenID CIBA Core 1.0 §10) ────────────────────────────

    private async Task<IResult> HandleCibaAsync(
        IFormCollection form, Client client,
        string? cnfJwkThumbprint, string? cnfX5tS256,
        CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains("urn:ietf:params:oauth:grant-type:ciba"))
            return TokenError(OAuthError.UnauthorizedClient("CIBA grant not allowed for this client"), 400);

        var authReqId = form["auth_req_id"].ToString();
        if (string.IsNullOrEmpty(authReqId))
            return TokenError(OAuthError.InvalidRequest("auth_req_id is required"), 400);

        var authRequest = await _cibaStore.FindAsync(authReqId, ct);
        if (authRequest is null)
            return TokenError(OAuthError.InvalidGrant("auth_req_id not found"), 400);

        if (authRequest.ClientId != client.ClientId)
            return TokenError(OAuthError.InvalidGrant("client_id mismatch"), 400);

        if (authRequest.ExpiresAt <= DateTimeOffset.UtcNow)
            return TokenError(OAuthError.ExpiredToken("auth_req_id has expired"), 400);

        // Enforce minimum polling interval
        var opts = _options.Value;
        var now = DateTimeOffset.UtcNow;
        if (authRequest.LastPolledAt.HasValue)
        {
            var elapsed = now - authRequest.LastPolledAt.Value;
            if (elapsed.TotalSeconds < opts.CibaPollingIntervalSeconds)
            {
                authRequest.LastPolledAt = now;
                var remaining = authRequest.ExpiresAt - now;
                if (remaining > TimeSpan.Zero)
                    await _cibaStore.StoreAsync(authReqId, authRequest, remaining, ct);
                return TokenError(OAuthError.SlowDown("polling too frequently"), 400);
            }
        }
        authRequest.LastPolledAt = now;

        switch (authRequest.Status)
        {
            case BackchannelAuthenticationStatus.Pending:
            {
                var remaining = authRequest.ExpiresAt - now;
                if (remaining > TimeSpan.Zero)
                    await _cibaStore.StoreAsync(authReqId, authRequest, remaining, ct);
                return TokenError(OAuthError.AuthorizationPending("user has not yet authenticated"), 400);
            }
            case BackchannelAuthenticationStatus.Denied:
                await _cibaStore.RemoveAsync(authReqId, ct);
                return TokenError(OAuthError.AccessDenied("user denied the authentication request"), 400);
        }

        // Approved — consume atomically so concurrent polls cannot both redeem it.
        if (await _cibaStore.ConsumeAsync(authReqId, ct) is null)
            return TokenError(OAuthError.InvalidGrant("auth_req_id already redeemed"), 400);

        var refresh = opts.IssueRefreshTokens
            ? await _refreshTokens.IssueAsync(
                client, authRequest.Subject!, authRequest.GrantedScopes, resources: [],
                authorizationDetailsJson: null, cnfJwkThumbprint, cnfX5tS256, ct)
            : null;
        var refreshTokenValue = refresh?.Value;

        var tokenId = GenerateId();
        var atValue = _tokenFactory.CreateAccessToken(
            tokenId, authRequest.Subject!, client.ClientId, authRequest.GrantedScopes,
            cnfJwkThumbprint, cnfX5tS256);

        var at = new AccessToken
        {
            TokenId = tokenId,
            GrantId = refresh?.GrantId ?? tokenId,
            ClientId = client.ClientId,
            Subject = authRequest.Subject,
            Scopes = authRequest.GrantedScopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AccessTokenLifetimeSeconds),
            CnfJwkThumbprint = cnfJwkThumbprint,
            CnfX5tS256 = cnfX5tS256,
        };
        await _accessTokenStore.StoreAsync(tokenId, at,
            TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);

        string? idToken = null;
        if (authRequest.GrantedScopes.Contains("openid"))
            idToken = _tokenFactory.CreateIdToken(
                authRequest.Subject!, client.ClientId, nonce: null,
                authTime: authRequest.CreatedAt,
                acr: null, amr: null, sid: null);

        return TokenSuccess(atValue, opts.AccessTokenLifetimeSeconds, refreshTokenValue, idToken,
            tokenType: cnfJwkThumbprint is not null ? "DPoP" : "Bearer");
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static IResult TokenSuccess(
        string accessToken, int expiresIn, string? refreshToken, string? idToken,
        string tokenType = "Bearer")
    {
        var body = BuildTokenBody(accessToken, expiresIn, refreshToken, idToken, tokenType);
        return Results.Json(body, statusCode: 200);
    }

    private static Dictionary<string, object> BuildTokenBody(
        string accessToken, int expiresIn, string? refreshToken, string? idToken,
        string tokenType = "Bearer")
    {
        var body = new Dictionary<string, object>
        {
            ["access_token"] = accessToken,
            ["token_type"] = tokenType,
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
