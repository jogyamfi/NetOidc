using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Token;

/// <summary>
/// Single place that decides whether a presented access token is live. JWT tokens must have a
/// valid signature and lifetime; opaque tokens are looked up by their hash. Either way the
/// stored record must exist (so revoked tokens fail) and, for tokens issued under a grant, the
/// grant must not have been revoked (RFC 7009 §2.1 revocation cascade).
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

    /// <summary>
    /// A live access token: its stored record and, for JWT tokens, the validated claims
    /// (<c>null</c> for opaque tokens — use the record).
    /// </summary>
    public sealed record ValidatedAccessToken(ClaimsPrincipal? Principal, AccessToken Record);

    /// <summary>Returns the token when it is live; otherwise <c>null</c>.</summary>
    public async Task<ValidatedAccessToken?> ValidateAsync(string rawToken, CancellationToken ct)
    {
        ClaimsPrincipal? principal = null;
        AccessToken? record;

        if (IsJwt(rawToken))
        {
            principal = await _tokenFactory.ValidateAccessTokenAsync(rawToken, ct);
            var jti = principal?.FindFirst("jti")?.Value;
            if (jti is null) return null;
            record = await _accessTokens.FindAsync(jti, ct);
            if (record?.Format != TokenFormat.Jwt) return null;
        }
        else
        {
            record = await _accessTokens.FindAsync(OpaqueTokenId(rawToken), ct);
            if (record?.Format != TokenFormat.Opaque) return null;
        }

        if (record is null || record.ExpiresAt <= DateTimeOffset.UtcNow)
            return null;

        // Tokens that belong to a grant (GrantId differs from their own id) die with it.
        if (record.GrantId != record.TokenId && await _grants.FindAsync(record.GrantId, ct) is null)
            return null;

        return new ValidatedAccessToken(principal, record);
    }

    /// <summary>
    /// Store key for an opaque token: its SHA-256 hash, so the stored records cannot be replayed
    /// as tokens if the store leaks.
    /// </summary>
    public static string OpaqueTokenId(string value) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    private static bool IsJwt(string token) => token.Count(c => c == '.') == 2;
}
