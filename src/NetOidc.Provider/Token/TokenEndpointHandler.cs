using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
/// device_code (RFC 8628), and CIBA grant types. Tokens are minted by
/// <see cref="TokenIssuanceService"/>.
/// </summary>
public sealed class TokenEndpointHandler
{
    // Token type URIs (RFC 8693 §3)
    private const string TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";
    private const string TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";
    private const string TokenTypeIdToken = "urn:ietf:params:oauth:token-type:id_token";

    private const string GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string GrantTypeJwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private const string GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
    private const string GrantTypeCiba = "urn:ietf:params:oauth:grant-type:ciba";

    private readonly IOptions<ProviderOptions> _options;
    private readonly ClientAuthenticator _clientAuthenticator;
    private readonly IAdapter<AuthorizationCode> _codeStore;
    private readonly RefreshTokenService _refreshTokens;
    private readonly IAdapter<DeviceCode> _deviceCodeStore;
    private readonly IAdapter<BackchannelAuthenticationRequest> _cibaStore;
    private readonly TokenFactory _tokenFactory;
    private readonly DPopProofValidator _dpopValidator;
    private readonly DPoPNonceService _dpopNonces;
    private readonly IReplayCache _replayCache;
    private readonly AccessTokenService _accessTokens;
    private readonly TokenIssuanceService _issuer;
    private readonly GrantService _grants;
    private readonly ILogger<TokenEndpointHandler> _logger;
    private readonly IProviderEventSink _events;

    public TokenEndpointHandler(
        IOptions<ProviderOptions> options,
        ClientAuthenticator clientAuthenticator,
        IAdapter<AuthorizationCode> codeStore,
        RefreshTokenService refreshTokens,
        IAdapter<DeviceCode> deviceCodeStore,
        IAdapter<BackchannelAuthenticationRequest> cibaStore,
        TokenFactory tokenFactory,
        DPopProofValidator dpopValidator,
        IReplayCache replayCache,
        AccessTokenService accessTokens,
        TokenIssuanceService issuer,
        GrantService grants,
        ILogger<TokenEndpointHandler> logger,
        DPoPNonceService dpopNonces,
        IProviderEventSink events)
    {
        _events = events;
        _dpopNonces = dpopNonces;
        _options = options;
        _clientAuthenticator = clientAuthenticator;
        _codeStore = codeStore;
        _refreshTokens = refreshTokens;
        _deviceCodeStore = deviceCodeStore;
        _cibaStore = cibaStore;
        _tokenFactory = tokenFactory;
        _dpopValidator = dpopValidator;
        _replayCache = replayCache;
        _accessTokens = accessTokens;
        _issuer = issuer;
        _grants = grants;
        _logger = logger;
    }

    /// <summary>Sender-constraint material presented with the token request.</summary>
    private sealed record Binding(string? Jkt, string? X5tS256);

    private const string ClientIdItem = "netoidc.token.client_id";

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var result = await HandleCoreAsync(context, ct);

        // One place records every rejected token request (client-auth failures are recorded
        // by the authenticator itself).
        if (result is Microsoft.AspNetCore.Http.HttpResults.JsonHttpResult<OAuthError> { Value: { } error } &&
            error.Error != "invalid_client")
        {
            var grantType = context.Request.HasFormContentType ? context.Request.Form["grant_type"].ToString() : string.Empty;
            var clientId = context.Items[ClientIdItem] as string;
            Diagnostics.Log.TokenRequestFailed(_logger, clientId, grantType, error.Error, error.Description);
            Diagnostics.NetOidcTelemetry.TokenRequestsFailed.Add(1,
                new KeyValuePair<string, object?>("grant_type", grantType),
                new KeyValuePair<string, object?>("error", error.Error));
            await _events.TokenRequestFailedAsync(new TokenRequestFailedEvent(
                clientId, grantType, error.Error, error.Description, DateTimeOffset.UtcNow), ct);
        }
        return result;
    }

    private async Task<IResult> HandleCoreAsync(HttpContext context, CancellationToken ct)
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
        context.Items[ClientIdItem] = client.ClientId;

        // ── DPoP proof validation (RFC 9449) ────────────────────────────────────
        string? cnfJwkThumbprint = null;
        var dpopHeader = context.Request.Headers["DPoP"].ToString();
        if (!string.IsNullOrEmpty(dpopHeader))
        {
            if (!opts.DPoPEnabled)
                return TokenError(OAuthError.InvalidRequest("DPoP is not supported by this server"), 400);

            var proof = await _dpopValidator.ValidateAsync(
                dpopHeader,
                context.Request.Method,
                opts.Issuer.TrimEnd('/') + opts.TokenEndpoint,
                accessToken: null,
                clockSkewSeconds: opts.DPoPProofLifetimeSeconds);

            if (proof is null)
                return TokenError(OAuthError.InvalidDPoPProof("DPoP proof is missing or invalid"), 400);

            // RFC 9449 §8: when nonces are required, hand out a fresh one and ask for a retry.
            if (_dpopNonces.IsRequired)
            {
                context.Response.Headers["DPoP-Nonce"] = _dpopNonces.Issue();
                if (!_dpopNonces.IsValid(proof.Nonce))
                    return TokenError(OAuthError.UseDPoPNonce("the DPoP proof must include the server-provided nonce"), 400);
            }
            cnfJwkThumbprint = proof.Thumbprint;
        }

        var isFapi2 = opts.FapiProfile is FapiProfile.Fapi2Security or FapiProfile.Fapi2MessageSigning or FapiProfile.FapiCiba;

        // ── mTLS certificate binding (RFC 8705 §3) ──────────────────────────────
        string? cnfX5tS256 = null;
        if (opts.MtlsEnabled && (client.UseMtlsBoundTokens || isFapi2) && cnfJwkThumbprint is null)
        {
            var cert = _clientAuthenticator.GetClientCertificate(context);
            if (cert is not null)
                cnfX5tS256 = ClientAuthenticator.ComputeCertThumbprint(cert);
        }

        // FAPI 2.0 §5.3.2.1: every access token must be sender-constrained.
        if (isFapi2 && cnfJwkThumbprint is null && cnfX5tS256 is null)
            return TokenError(OAuthError.InvalidRequest(
                "FAPI 2.0: sender-constrained tokens are required (present a DPoP proof or client certificate)"), 400);

        var binding = new Binding(cnfJwkThumbprint, cnfX5tS256);
        var grantType = form["grant_type"].ToString();
        return grantType switch
        {
            "authorization_code" => await HandleAuthorizationCodeAsync(form, client, binding, ct),
            "refresh_token" => await HandleRefreshTokenAsync(form, client, binding, ct),
            "client_credentials" => await HandleClientCredentialsAsync(form, client, binding, ct),
            GrantTypeTokenExchange when opts.TokenExchangeEnabled
                => await HandleTokenExchangeAsync(form, client, binding, ct),
            GrantTypeJwtBearer when opts.JwtBearerGrantEnabled
                => await HandleJwtBearerAsync(form, client, binding, ct),
            GrantTypeDeviceCode when opts.DeviceFlowEnabled
                => await HandleDeviceCodeAsync(form, client, binding, ct),
            GrantTypeCiba when opts.CibaEnabled
                => await HandleCibaAsync(form, client, binding, ct),
            _ => TokenError(OAuthError.UnsupportedGrantType(), 400),
        };
    }

    // ── authorization_code grant ───────────────────────────────────────────────

    private async Task<IResult> HandleAuthorizationCodeAsync(
        IFormCollection form, Client client, Binding binding, CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains("authorization_code"))
            return TokenError(OAuthError.UnauthorizedClient("authorization_code not allowed for this client"), 400);

        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        if (string.IsNullOrEmpty(code))
            return TokenError(OAuthError.InvalidRequest("code is required"), 400);

        var authCode = await _codeStore.ConsumeAsync(code, ct);
        if (authCode is null)
            return TokenError(OAuthError.InvalidGrant("authorization code not found or already used"), 400);

        if (authCode.ConsumedAt is not null)
        {
            // RFC 6749 §4.1.2: a replayed code revokes every token issued from it.
            if (authCode.GrantId is not null)
                await _grants.RevokeAsync(authCode.GrantId, ct);
            await StoreCodeTombstoneAsync(code, authCode, ct);
            return TokenError(OAuthError.InvalidGrant("authorization code already used; issued tokens were revoked"), 400);
        }
        await StoreCodeTombstoneAsync(code, authCode, ct);

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

        // PKCE (RFC 7636 §4.6). A verifier without a challenge is a downgrade attempt (RFC 9700 §2.1.1).
        if (authCode.CodeChallenge is not null)
        {
            if (string.IsNullOrEmpty(codeVerifier))
                return TokenError(OAuthError.InvalidRequest("code_verifier is required"), 400);
            if (!PkceValidator.Validate(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod ?? "plain"))
                return TokenError(OAuthError.InvalidGrant("code_verifier does not match code_challenge"), 400);
        }
        else if (!string.IsNullOrEmpty(codeVerifier))
        {
            return TokenError(OAuthError.InvalidGrant("code_verifier supplied but no code_challenge was sent"), 400);
        }

        var (resources, resourceError) = NarrowResources(form, authCode.Resources);
        if (resourceError is not null)
            return TokenError(resourceError, 400);

        var issued = await _issuer.IssueAsync(new TokenIssuanceRequest
        {
            Client = client,
            GrantType = "authorization_code",
            Subject = authCode.Subject,
            Scopes = authCode.Scopes,
            Resources = resources,
            AuthorizationDetailsJson = authCode.AuthorizationDetailsJson,
            CnfJwkThumbprint = binding.Jkt,
            CnfX5tS256 = binding.X5tS256,
            GrantId = authCode.GrantId,
            IncludeRefreshToken = true,
            ClaimsRequest = authCode.ClaimsRequest,
            IdToken = new IdTokenParameters(authCode.AuthTime, authCode.Nonce, authCode.Acr, authCode.Amr,
                authCode.SessionId, authCode.ClaimsRequest),
        }, ct);

        var body = BuildTokenBody(issued);
        if (authCode.AuthorizationDetailsJson is not null)
            body["authorization_details"] = System.Text.Json.JsonSerializer.Deserialize<object>(authCode.AuthorizationDetailsJson)!;
        return Results.Json(body, statusCode: 200);
    }

    private Task StoreCodeTombstoneAsync(string code, AuthorizationCode authCode, CancellationToken ct)
    {
        // Kept for the access-token lifetime so a late replay can still revoke what was issued.
        var lifetime = TimeSpan.FromSeconds(_options.Value.AccessTokenLifetimeSeconds);
        return _codeStore.StoreAsync(code, new AuthorizationCode
        {
            Code = authCode.Code,
            ClientId = authCode.ClientId,
            RedirectUri = authCode.RedirectUri,
            Subject = authCode.Subject,
            AuthTime = authCode.AuthTime,
            ExpiresAt = authCode.ExpiresAt,
            GrantId = authCode.GrantId,
            ConsumedAt = authCode.ConsumedAt ?? DateTimeOffset.UtcNow,
        }, lifetime, ct);
    }

    // ── refresh_token grant (RFC 6749 §6) ─────────────────────────────────────

    private async Task<IResult> HandleRefreshTokenAsync(
        IFormCollection form, Client client, Binding binding, CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains("refresh_token"))
            return TokenError(OAuthError.UnauthorizedClient("refresh_token not allowed for this client"), 400);

        var rtValue = form["refresh_token"].ToString();
        if (string.IsNullOrEmpty(rtValue))
            return TokenError(OAuthError.InvalidRequest("refresh_token is required"), 400);

        var redemption = await _refreshTokens.RedeemAsync(rtValue, client, binding.Jkt, binding.X5tS256, ct);
        if (!redemption.Succeeded)
            return TokenError(OAuthError.InvalidGrant(redemption.Error), 400);
        var rt = redemption.Token!;

        // RFC 6749 §6: a narrower scope may be requested; the refresh token keeps the original.
        var scopes = rt.Scopes;
        var scopeParam = form["scope"].ToString();
        if (!string.IsNullOrEmpty(scopeParam))
        {
            var requested = scopeParam.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();
            var excess = requested.Where(s => !rt.Scopes.Contains(s)).ToList();
            if (excess.Count > 0)
                return TokenError(OAuthError.InvalidScope($"Scope(s) not originally granted: {string.Join(" ", excess)}"), 400);
            scopes = requested;
        }

        var (resources, resourceError) = NarrowResources(form, rt.Resources);
        if (resourceError is not null)
            return TokenError(resourceError, 400);

        var issued = await _issuer.IssueAsync(new TokenIssuanceRequest
        {
            Client = client,
            GrantType = "refresh_token",
            Subject = rt.Subject,
            Scopes = scopes,
            Resources = resources,
            AuthorizationDetailsJson = rt.AuthorizationDetailsJson,
            CnfJwkThumbprint = binding.Jkt,
            CnfX5tS256 = binding.X5tS256,
            PreviousRefreshToken = rt,
            RefreshTokenRotated = redemption.Rotated,
            ClaimsRequest = rt.ClaimsRequest,
            // OIDC Core §12.2: a refreshed ID token carries the original authentication context.
            IdToken = rt.AuthTime is { } authTime
                ? new IdTokenParameters(authTime, Acr: rt.Acr, Amr: rt.Amr, SessionId: rt.SessionId,
                    ClaimsRequest: rt.ClaimsRequest)
                : null,
        }, ct);

        return Results.Json(BuildTokenBody(issued), statusCode: 200);
    }

    // ── client_credentials grant ───────────────────────────────────────────────

    private async Task<IResult> HandleClientCredentialsAsync(
        IFormCollection form, Client client, Binding binding, CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains("client_credentials"))
            return TokenError(OAuthError.UnauthorizedClient("client_credentials not allowed for this client"), 400);

        var (requestedScopes, scopeError) = ValidateScopes(form["scope"].ToString(), client);
        if (scopeError is not null)
            return TokenError(scopeError, 400);

        var (resources, resourceError) = RequestedResources(form, client);
        if (resourceError is not null)
            return TokenError(resourceError, 400);

        var issued = await _issuer.IssueAsync(new TokenIssuanceRequest
        {
            Client = client,
            GrantType = "client_credentials",
            Scopes = requestedScopes,
            Resources = resources,
            CnfJwkThumbprint = binding.Jkt,
            CnfX5tS256 = binding.X5tS256,
        }, ct);

        return Results.Json(BuildTokenBody(issued), statusCode: 200);
    }

    // ── token-exchange grant (RFC 8693) ───────────────────────────────────────

    private async Task<IResult> HandleTokenExchangeAsync(
        IFormCollection form, Client client, Binding binding, CancellationToken ct)
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
                subject = live.Record.Subject;
                subjectClientId = live.Record.ClientId;
                subjectScopes = live.Record.Scopes;
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
                // The ID token carries the (possibly pairwise) subject as issued to its client.
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

        var (resources, resourceError) = RequestedResources(form, client);
        if (resourceError is not null)
            return TokenError(resourceError, 400);

        var opts = _options.Value;
        var exchange = new TokenExchangeContext(
            client.ClientId, subjectClientId, subject, subjectTokenType,
            subjectScopes, requestedScopes,
            form["audience"].Where(a => !string.IsNullOrEmpty(a)).Select(a => a!).ToList(),
            resources);

        var permitted = opts.AuthorizeTokenExchange is null
            ? subjectClientId == client.ClientId
            : await opts.AuthorizeTokenExchange(exchange, ct);
        if (!permitted)
            return TokenError(OAuthError.InvalidGrant("client is not permitted to exchange this subject_token"), 400);

        var issued = await _issuer.IssueAsync(new TokenIssuanceRequest
        {
            Client = client,
            GrantType = GrantTypeTokenExchange,
            Subject = subject,
            Scopes = requestedScopes,
            Resources = resources,
            CnfJwkThumbprint = binding.Jkt,
            CnfX5tS256 = binding.X5tS256,
        }, ct);

        var body = BuildTokenBody(issued);
        body["issued_token_type"] = TokenTypeAccessToken;
        return Results.Json(body, statusCode: 200);
    }

    // ── jwt-bearer grant (RFC 7523) ────────────────────────────────────────────

    private async Task<IResult> HandleJwtBearerAsync(
        IFormCollection form, Client client, Binding binding, CancellationToken ct)
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

        var subject = result.Claims.TryGetValue("sub", out var subVal) ? subVal?.ToString() : null;

        // RFC 7523 §3: jti enables one-time use; require it and refuse replays.
        var jti = result.Claims.TryGetValue("jti", out var jtiVal) ? jtiVal?.ToString() : null;
        if (string.IsNullOrEmpty(jti))
            return TokenError(OAuthError.InvalidGrant("assertion must contain a jti claim"), 400);
        var assertionExpiry = result.SecurityToken.ValidTo == DateTime.MinValue
            ? DateTimeOffset.UtcNow.AddMinutes(10)
            : new DateTimeOffset(result.SecurityToken.ValidTo, TimeSpan.Zero).AddSeconds(30);
        if (!await _replayCache.TryAddAsync($"jwt-bearer:{client.ClientId}:{jti}", assertionExpiry, ct))
            return TokenError(OAuthError.InvalidGrant("assertion has already been used"), 400);

        var (requestedScopes, scopeError) = ValidateScopes(form["scope"].ToString(), client);
        if (scopeError is not null)
            return TokenError(scopeError, 400);

        // Only the operator can say which subjects a client may speak for.
        var permitted = opts.AuthorizeJwtBearerSubject is not null &&
            await opts.AuthorizeJwtBearerSubject(
                new JwtBearerContext(client.ClientId, subject, requestedScopes), ct);
        if (!permitted)
            return TokenError(OAuthError.InvalidGrant("client is not permitted to assert this subject"), 400);

        var (resources, resourceError) = RequestedResources(form, client);
        if (resourceError is not null)
            return TokenError(resourceError, 400);

        var issued = await _issuer.IssueAsync(new TokenIssuanceRequest
        {
            Client = client,
            GrantType = GrantTypeJwtBearer,
            Subject = subject,
            Scopes = requestedScopes,
            Resources = resources,
            CnfJwkThumbprint = binding.Jkt,
            CnfX5tS256 = binding.X5tS256,
        }, ct);

        return Results.Json(BuildTokenBody(issued), statusCode: 200);
    }

    // ── device_code grant (RFC 8628 §3.4) ────────────────────────────────────

    private async Task<IResult> HandleDeviceCodeAsync(
        IFormCollection form, Client client, Binding binding, CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains(GrantTypeDeviceCode))
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

        // RFC 8628 §3.5: enforce the interval, and add 5 seconds on every slow_down.
        var now = DateTimeOffset.UtcNow;
        var remaining = deviceCode.ExpiresAt - now;
        if (deviceCode.LastPolledAt.HasValue &&
            (now - deviceCode.LastPolledAt.Value).TotalSeconds < deviceCode.IntervalSeconds)
        {
            deviceCode.LastPolledAt = now;
            deviceCode.IntervalSeconds += 5;
            await _deviceCodeStore.StoreAsync(deviceCodeValue, deviceCode, remaining, ct);
            return TokenError(OAuthError.SlowDown($"polling too frequently; wait {deviceCode.IntervalSeconds} seconds"), 400);
        }
        deviceCode.LastPolledAt = now;

        switch (deviceCode.Status)
        {
            case DeviceCodeStatus.Pending:
                await _deviceCodeStore.StoreAsync(deviceCodeValue, deviceCode, remaining, ct);
                return TokenError(OAuthError.AuthorizationPending("user has not yet authorized"), 400);
            case DeviceCodeStatus.Denied:
                await _deviceCodeStore.RemoveAsync(deviceCodeValue, ct);
                return TokenError(OAuthError.AccessDenied("user denied the authorization request"), 400);
        }

        // Approved — consume atomically so concurrent polls cannot both redeem it.
        if (await _deviceCodeStore.ConsumeAsync(deviceCodeValue, ct) is null)
            return TokenError(OAuthError.InvalidGrant("device code already redeemed"), 400);

        var issued = await _issuer.IssueAsync(new TokenIssuanceRequest
        {
            Client = client,
            GrantType = GrantTypeDeviceCode,
            Subject = deviceCode.Subject!,
            Scopes = deviceCode.GrantedScopes,
            CnfJwkThumbprint = binding.Jkt,
            CnfX5tS256 = binding.X5tS256,
            IncludeRefreshToken = true,
            IdToken = new IdTokenParameters(deviceCode.AuthTime ?? deviceCode.CreatedAt),
        }, ct);

        return Results.Json(BuildTokenBody(issued), statusCode: 200);
    }

    // ── CIBA poll/ping grant (OpenID CIBA Core 1.0 §10) ───────────────────────

    private async Task<IResult> HandleCibaAsync(
        IFormCollection form, Client client, Binding binding, CancellationToken ct)
    {
        if (!client.AllowedGrantTypes.Contains(GrantTypeCiba))
            return TokenError(OAuthError.UnauthorizedClient("CIBA grant not allowed for this client"), 400);

        // CIBA §10.3: push-mode clients receive tokens at their notification endpoint.
        if (client.CibaDeliveryMode == "push")
            return TokenError(OAuthError.UnauthorizedClient("push-mode clients cannot poll the token endpoint"), 400);

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

        // Poll mode: enforce the minimum interval. Ping-mode clients only poll once notified.
        var opts = _options.Value;
        var now = DateTimeOffset.UtcNow;
        var remaining = authRequest.ExpiresAt - now;
        if (authRequest.DeliveryMode == "poll" && authRequest.LastPolledAt.HasValue &&
            (now - authRequest.LastPolledAt.Value).TotalSeconds < opts.CibaPollingIntervalSeconds)
        {
            authRequest.LastPolledAt = now;
            await _cibaStore.StoreAsync(authReqId, authRequest, remaining, ct);
            return TokenError(OAuthError.SlowDown("polling too frequently"), 400);
        }
        authRequest.LastPolledAt = now;

        switch (authRequest.Status)
        {
            case BackchannelAuthenticationStatus.Pending:
                await _cibaStore.StoreAsync(authReqId, authRequest, remaining, ct);
                return TokenError(OAuthError.AuthorizationPending("user has not yet authenticated"), 400);
            case BackchannelAuthenticationStatus.Denied:
                await _cibaStore.RemoveAsync(authReqId, ct);
                return TokenError(OAuthError.AccessDenied("user denied the authentication request"), 400);
        }

        // Approved — consume atomically so concurrent polls cannot both redeem it.
        if (await _cibaStore.ConsumeAsync(authReqId, ct) is null)
            return TokenError(OAuthError.InvalidGrant("auth_req_id already redeemed"), 400);

        var issued = await _issuer.IssueAsync(CibaTokenRequest(client, authRequest, binding.Jkt, binding.X5tS256), ct);
        return Results.Json(BuildTokenBody(issued), statusCode: 200);
    }

    /// <summary>The token issuance request for an approved CIBA authentication request.</summary>
    internal static TokenIssuanceRequest CibaTokenRequest(
        Client client, BackchannelAuthenticationRequest authRequest, string? jkt, string? x5t) => new()
    {
        Client = client,
        GrantType = GrantTypeCiba,
        Subject = authRequest.Subject!,
        Scopes = authRequest.GrantedScopes,
        CnfJwkThumbprint = jkt,
        CnfX5tS256 = x5t,
        IncludeRefreshToken = true,
        IdToken = new IdTokenParameters(authRequest.AuthTime ?? authRequest.CreatedAt, Acr: authRequest.Acr),
    };

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>Validates a requested scope string (default: all client scopes).</summary>
    private (List<string> Scopes, OAuthError? Error) ValidateScopes(string scopeStr, Client client)
    {
        var requested = string.IsNullOrEmpty(scopeStr)
            ? client.AllowedScopes.ToList()
            : scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();

        var registered = _options.Value.Scopes.Select(s => s.Name).ToHashSet();
        var unknown = requested.Where(s => !registered.Contains(s)).ToList();
        if (unknown.Count > 0)
            return ([], OAuthError.InvalidScope($"Unknown scope(s): {string.Join(" ", unknown)}"));

        var disallowed = requested.Where(s => !client.AllowedScopes.Contains(s)).ToList();
        if (disallowed.Count > 0)
            return ([], OAuthError.InvalidScope($"Client not authorized for scope(s): {string.Join(" ", disallowed)}"));

        return (requested, null);
    }

    /// <summary>
    /// RFC 8707 §2.2: at a code or refresh grant, <c>resource</c> may narrow the audience to a
    /// subset of what was authorized; without it every authorized resource applies.
    /// </summary>
    private (IReadOnlyList<string> Resources, OAuthError? Error) NarrowResources(
        IFormCollection form, IReadOnlyList<string> authorized)
    {
        var requested = form["resource"].Where(r => !string.IsNullOrEmpty(r)).Select(r => r!).Distinct().ToList();
        if (requested.Count == 0) return (authorized, null);
        if (!_options.Value.ResourceIndicatorsEnabled)
            return ([], OAuthError.InvalidTarget("resource indicators are not enabled"));
        var excess = requested.Where(r => !authorized.Contains(r)).ToList();
        return excess.Count > 0
            ? ([], OAuthError.InvalidTarget($"resource(s) not authorized: {string.Join(" ", excess)}"))
            : (requested, null);
    }

    /// <summary>Validates <c>resource</c> parameters for grants without a prior authorization.</summary>
    private (IReadOnlyList<string> Resources, OAuthError? Error) RequestedResources(IFormCollection form, Client client)
    {
        var requested = form["resource"].Where(r => !string.IsNullOrEmpty(r)).Select(r => r!).Distinct().ToList();
        if (requested.Count == 0) return ([], null);
        var opts = _options.Value;
        if (!opts.ResourceIndicatorsEnabled)
            return ([], OAuthError.InvalidTarget("resource indicators are not enabled"));
        return ResourceIndicators.Validate(requested, opts, client) is { } error
            ? ([], OAuthError.InvalidTarget(error))
            : (requested, null);
    }

    private static Dictionary<string, object> BuildTokenBody(IssuedTokens issued)
    {
        var body = new Dictionary<string, object>
        {
            ["access_token"] = issued.AccessToken,
            ["token_type"] = issued.TokenType,
            ["expires_in"] = issued.ExpiresIn,
            ["scope"] = string.Join(' ', issued.AccessTokenRecord.Scopes),
        };
        if (issued.RefreshToken is not null) body["refresh_token"] = issued.RefreshToken;
        if (issued.IdToken is not null) body["id_token"] = issued.IdToken;
        return body;
    }

    private static IResult TokenError(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
