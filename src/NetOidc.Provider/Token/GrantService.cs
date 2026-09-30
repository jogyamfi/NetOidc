using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Token;

/// <summary>
/// Manages <see cref="Grant"/> records: the lineage that ties an authorization code, its
/// refresh-token family and the access tokens issued from them. Removing a grant revokes
/// everything issued under it (RFC 6749 §4.1.2, RFC 7009 §2.1).
/// </summary>
internal sealed class GrantService
{
    private readonly IAdapter<Grant> _grants;

    public GrantService(IAdapter<Grant> grants) => _grants = grants;

    /// <summary>Creates a grant that lives for <paramref name="lifetime"/> unless extended.</summary>
    public async Task<string> CreateAsync(
        string clientId, string subject, IReadOnlyList<string> scopes, TimeSpan lifetime, CancellationToken ct)
    {
        var id = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow;
        await _grants.StoreAsync(id, new Grant
        {
            GrantId = id,
            ClientId = clientId,
            Subject = subject,
            GrantedScopes = scopes,
            CreatedAt = now,
            ExpiresAt = now + lifetime,
        }, lifetime, ct);
        return id;
    }

    /// <summary>
    /// Ensures the grant lives at least <paramref name="lifetime"/> from now. Returns false when
    /// the grant no longer exists (revoked or expired).
    /// </summary>
    public async Task<bool> ExtendAsync(string grantId, TimeSpan lifetime, CancellationToken ct)
    {
        var grant = await _grants.FindAsync(grantId, ct);
        if (grant is null) return false;

        var wanted = DateTimeOffset.UtcNow + lifetime;
        if (grant.ExpiresAt is { } current && current >= wanted) return true;

        await _grants.StoreAsync(grantId, new Grant
        {
            GrantId = grant.GrantId,
            ClientId = grant.ClientId,
            Subject = grant.Subject,
            GrantedScopes = grant.GrantedScopes,
            CreatedAt = grant.CreatedAt,
            ExpiresAt = wanted,
        }, lifetime, ct);
        return true;
    }

    /// <summary>Returns true while the grant exists.</summary>
    public async Task<bool> IsActiveAsync(string grantId, CancellationToken ct) =>
        await _grants.FindAsync(grantId, ct) is not null;

    /// <summary>Revokes the grant and, with it, every token issued under it.</summary>
    public Task RevokeAsync(string grantId, CancellationToken ct) => _grants.RemoveAsync(grantId, ct);
}
