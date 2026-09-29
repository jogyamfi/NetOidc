using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Token;

/// <summary>Authentication context needed to mint an ID token.</summary>
/// <param name="IncludeScopeClaims">
/// Put scope-derived End-User claims in the ID token. OIDC Core §5.4 requires this only when no
/// access token is issued (<c>response_type=id_token</c>).
/// </param>
public sealed record IdTokenParameters(
    DateTimeOffset AuthTime,
    string? Nonce = null,
    string? Acr = null,
    IReadOnlyList<string>? Amr = null,
    string? SessionId = null,
    string? ClaimsRequest = null,
    string? Code = null,
    bool IncludeScopeClaims = false,
    IReadOnlyDictionary<string, object>? ExtraClaims = null);

/// <summary>Everything needed to issue tokens for one grant.</summary>
public sealed record TokenIssuanceRequest
{
    public required Client Client { get; init; }

    /// <summary>Grant type, reported in <see cref="TokenIssuedEvent"/>.</summary>
    public required string GrantType { get; init; }

    /// <summary>The End-User's local subject, or <c>null</c> for client-only tokens.</summary>
    public string? Subject { get; init; }

    public required IReadOnlyList<string> Scopes { get; init; }
    public IReadOnlyList<string> Resources { get; init; } = [];
    public string? AuthorizationDetailsJson { get; init; }
    public string? CnfJwkThumbprint { get; init; }
    public string? CnfX5tS256 { get; init; }

    /// <summary>Existing grant to join (e.g. the authorization code's), or <c>null</c>.</summary>
    public string? GrantId { get; init; }

    /// <summary>Issue a refresh token (subject to client policy).</summary>
    public bool IncludeRefreshToken { get; init; }

    /// <summary>
    /// The refresh token being redeemed. The new refresh token continues its family; when
    /// <see cref="RefreshTokenRotated"/> is false the presented value is returned unchanged.
    /// </summary>
    public RefreshToken? PreviousRefreshToken { get; init; }

    public bool RefreshTokenRotated { get; init; } = true;

    /// <summary>ID token parameters; <c>null</c> for no ID token.</summary>
    public IdTokenParameters? IdToken { get; init; }

    /// <summary>Raw <c>claims</c> request carried to UserInfo (via the access token) and refresh.</summary>
    public string? ClaimsRequest { get; init; }
}

/// <summary>The tokens minted for one request.</summary>
public sealed record IssuedTokens(
    string AccessToken,
    AccessToken AccessTokenRecord,
    string? RefreshToken,
    string? IdToken,
    int ExpiresIn,
    string TokenType);

/// <summary>
/// Single place that mints access, refresh and ID tokens: pairwise subjects, resource
/// audiences, grant lineage, sender constraint, <c>at_hash</c>/<c>c_hash</c> and claims release.
/// </summary>
public sealed class TokenIssuanceService
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly TokenFactory _tokenFactory;
    private readonly IAdapter<AccessToken> _accessTokens;
    private readonly RefreshTokenService _refreshTokens;
    private readonly GrantService _grants;
    private readonly SubjectIdentifierService _subjects;
    private readonly UserClaimsService _userClaims;
    private readonly IProviderEventSink _events;
    private readonly Microsoft.Extensions.Logging.ILogger<TokenIssuanceService> _logger;

    public TokenIssuanceService(
        IOptions<ProviderOptions> options,
        TokenFactory tokenFactory,
        IAdapter<AccessToken> accessTokens,
        RefreshTokenService refreshTokens,
        GrantService grants,
        SubjectIdentifierService subjects,
        UserClaimsService userClaims,
        IProviderEventSink events,
        Microsoft.Extensions.Logging.ILogger<TokenIssuanceService> logger)
    {
        _logger = logger;
        _options = options;
        _tokenFactory = tokenFactory;
        _accessTokens = accessTokens;
        _refreshTokens = refreshTokens;
        _grants = grants;
        _subjects = subjects;
        _userClaims = userClaims;
        _events = events;
    }

    /// <summary>Issues an access token plus, where requested and permitted, refresh and ID tokens.</summary>
    public async Task<IssuedTokens> IssueAsync(TokenIssuanceRequest request, CancellationToken ct)
    {
        var opts = _options.Value;
        var client = request.Client;
        var accessLifetime = TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds);

        // ── Refresh token (first, so the access token can join its grant) ─────
        string? refreshValue = null;
        var grantId = request.GrantId;
        if (request.PreviousRefreshToken is { } previous)
        {
            if (request.RefreshTokenRotated)
            {
                var successor = await _refreshTokens.IssueSuccessorAsync(client, previous, ct);
                refreshValue = successor.Value;
                grantId = successor.GrantId;
            }
            else
            {
                refreshValue = previous.TokenId;
                grantId = previous.GrantId;
            }
        }
        else if (request.IncludeRefreshToken && request.Subject is not null && CanIssueRefreshToken(client))
        {
            var issued = await _refreshTokens.IssueAsync(client,
                new RefreshTokenContent(request.Subject, request.Scopes, request.Resources,
                    request.AuthorizationDetailsJson, request.IdToken?.AuthTime, request.IdToken?.Acr,
                    request.IdToken?.Amr, request.IdToken?.SessionId, request.ClaimsRequest),
                grantId, request.CnfJwkThumbprint, request.CnfX5tS256, ct);
            refreshValue = issued.Value;
            grantId = issued.GrantId;
        }
        else if (grantId is not null)
        {
            // No refresh token: the grant only needs to outlive the access token.
            await _grants.ExtendAsync(grantId, accessLifetime, ct);
        }

        // ── Access token ─────────────────────────────────────────────────────
        var format = client.AccessTokenFormat ?? opts.AccessTokenFormat;
        string tokenId, accessToken;
        if (format == TokenFormat.Opaque)
        {
            // A random reference; only its hash is stored (see AccessTokenService.OpaqueTokenId).
            accessToken = GenerateId();
            tokenId = AccessTokenService.OpaqueTokenId(accessToken);
        }
        else
        {
            tokenId = GenerateId();
            var publicSubject = request.Subject is null ? null : _subjects.Compute(request.Subject, client);
            accessToken = _tokenFactory.CreateAccessToken(
                tokenId, publicSubject, client.ClientId, request.Scopes,
                request.CnfJwkThumbprint, request.CnfX5tS256, request.Resources);
        }

        var record = new AccessToken
        {
            TokenId = tokenId,
            GrantId = grantId ?? tokenId,
            Format = format,
            ClientId = client.ClientId,
            Subject = request.Subject,
            Scopes = request.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow + accessLifetime,
            Resources = request.Resources,
            AuthorizationDetailsJson = request.AuthorizationDetailsJson,
            ClaimsRequest = request.ClaimsRequest,
            CnfJwkThumbprint = request.CnfJwkThumbprint,
            CnfX5tS256 = request.CnfX5tS256,
        };
        await _accessTokens.StoreAsync(tokenId, record, accessLifetime, ct);

        // ── ID token ─────────────────────────────────────────────────────────
        string? idToken = null;
        if (request.IdToken is { } idParams && request.Subject is not null && request.Scopes.Contains("openid"))
            idToken = await CreateIdTokenAsync(client, request.Subject, request.Scopes, idParams, accessToken, ct);

        Diagnostics.Log.TokensIssued(_logger, client.ClientId, request.GrantType);
        Diagnostics.NetOidcTelemetry.TokensIssued.Add(1,
            new KeyValuePair<string, object?>("grant_type", request.GrantType));
        await _events.TokenIssuedAsync(new TokenIssuedEvent(
            client.ClientId, request.Subject, request.GrantType, request.Scopes, DateTimeOffset.UtcNow), ct);

        return new IssuedTokens(accessToken, record, refreshValue, idToken,
            opts.AccessTokenLifetimeSeconds, request.CnfJwkThumbprint is not null ? "DPoP" : "Bearer");
    }

    /// <summary>
    /// Mints an ID token for <paramref name="localSubject"/>. When <paramref name="accessToken"/>
    /// is supplied its <c>at_hash</c> is included; a code in <paramref name="parameters"/> adds
    /// <c>c_hash</c>.
    /// </summary>
    public async Task<string> CreateIdTokenAsync(
        Client client, string localSubject, IReadOnlyList<string> scopes,
        IdTokenParameters parameters, string? accessToken, CancellationToken ct)
    {
        var claims = await _userClaims.GetClaimsAsync(
            localSubject, client, scopes, ClaimsEngine.Parse(parameters.ClaimsRequest),
            ClaimsDestination.IdToken, parameters.IncludeScopeClaims, ct);
        if (parameters.ExtraClaims is not null)
            foreach (var (name, value) in parameters.ExtraClaims)
                claims[name] = value;

        return _tokenFactory.CreateIdToken(
            _subjects.Compute(localSubject, client), client.ClientId, parameters.Nonce, parameters.AuthTime,
            acr: parameters.Acr, amr: parameters.Amr, additionalClaims: claims, sid: parameters.SessionId,
            client: client, accessToken: accessToken, code: parameters.Code);
    }

    /// <summary>
    /// A refresh token is issued only when the provider allows it and the client registered the
    /// <c>refresh_token</c> grant type (RFC 7591 §2).
    /// </summary>
    public bool CanIssueRefreshToken(Client client) =>
        _options.Value.IssueRefreshTokens && client.AllowedGrantTypes.Contains("refresh_token");

    private static string GenerateId() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
