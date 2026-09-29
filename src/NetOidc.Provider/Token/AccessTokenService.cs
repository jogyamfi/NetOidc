using System.Security.Claims;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Token;

/// <summary>
/// Single place that decides whether a presented access token is live: valid signature and
/// lifetime, a stored record (so revoked tokens fail), and — for tokens issued with a refresh
/// token — a grant that has not been revoked (RFC 7009 §2.1 revocation cascade).
/// </summary>
public sealed class AccessTokenService
{
    private readonly TokenFactory _tokenFactory;
    private readonly IAdapter<AccessToken> _accessTokens;
    private readonly IAdapter<Grant> _grants;

    public AccessTokenService(
        TokenFactory tokenFactory, IAdapter<AccessToken> accessTokens, IAdapter<Grant> grants)
    {
        _tokenFactory = tokenFactory;
        _accessTokens = accessTokens;
        _grants = grants;
    }

    /// <summary>A live access token: its validated claims and its stored record.</summary>
    public sealed record ValidatedAccessToken(ClaimsPrincipal Principal, AccessToken Record);

    /// <summary>Returns the token when it is live; otherwise <c>null</c>.</summary>
    public async Task<ValidatedAccessToken?> ValidateAsync(string rawToken, CancellationToken ct)
    {
        var principal = await _tokenFactory.ValidateAccessTokenAsync(rawToken, ct);
        var jti = principal?.FindFirst("jti")?.Value;
        if (principal is null || jti is null)
            return null;

        var record = await _accessTokens.FindAsync(jti, ct);
        if (record is null || record.ExpiresAt <= DateTimeOffset.UtcNow)
            return null;

        // Tokens that belong to a grant (GrantId differs from their own id) die with it.
        if (record.GrantId != record.TokenId && await _grants.FindAsync(record.GrantId, ct) is null)
            return null;

        return new ValidatedAccessToken(principal, record);
    }
}
