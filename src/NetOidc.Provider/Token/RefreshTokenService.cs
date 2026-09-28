using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Token;

/// <summary>
/// Owns the refresh-token lifecycle: issuance into a rotation family, one-time rotation,
/// reuse detection (OAuth 2.0 Security BCP, RFC 9700 §4.14.2) and sender-constraint checks
/// (RFC 9449 §5, RFC 8705 §4).
/// </summary>
public sealed class RefreshTokenService
{
    private readonly IAdapter<RefreshToken> _tokens;
    private readonly IAdapter<Grant> _grants;
    private readonly IOptions<ProviderOptions> _options;

    public RefreshTokenService(
        IAdapter<RefreshToken> tokens, IAdapter<Grant> grants, IOptions<ProviderOptions> options)
    {
        _tokens = tokens;
        _grants = grants;
        _options = options;
    }

    /// <summary>Outcome of <see cref="RotateAsync"/>.</summary>
    public sealed record RotationResult(RefreshToken? Token, string? Error)
    {
        public bool Succeeded => Token is not null;
    }

    /// <summary>
    /// Issues a new refresh token family. Tokens for public clients are bound to the presented
    /// DPoP key / client certificate; confidential clients are constrained by client authentication.
    /// </summary>
    public Task<string> IssueAsync(
        Client client, string subject, IReadOnlyList<string> scopes,
        IReadOnlyList<string> resources, string? authorizationDetailsJson,
        string? cnfJwkThumbprint, string? cnfX5tS256, CancellationToken ct)
    {
        var isPublic = client.TokenEndpointAuthMethod == "none";
        return StoreAsync(client, subject, scopes, resources, authorizationDetailsJson, grantId: null,
            isPublic ? cnfJwkThumbprint : null, isPublic ? cnfX5tS256 : null, ct);
    }

    /// <summary>
    /// Issues the successor of <paramref name="previous"/> (already validated by
    /// <see cref="RotateAsync"/>) in the same family, carrying over its binding.
    /// </summary>
    public Task<string> IssueSuccessorAsync(Client client, RefreshToken previous, CancellationToken ct) =>
        StoreAsync(client, previous.Subject, previous.Scopes, previous.Resources,
            previous.AuthorizationDetailsJson, previous.GrantId,
            previous.CnfJwkThumbprint, previous.CnfX5tS256, ct);

    private async Task<string> StoreAsync(
        Client client, string subject, IReadOnlyList<string> scopes,
        IReadOnlyList<string> resources, string? authorizationDetailsJson,
        string? grantId, string? boundJkt, string? boundX5t, CancellationToken ct)
    {
        var lifetime = TimeSpan.FromSeconds(_options.Value.RefreshTokenLifetimeSeconds);
        var now = DateTimeOffset.UtcNow;

        // Start a family, or slide an existing family's expiry along with the new token.
        var createdAt = now;
        if (grantId is not null && await _grants.FindAsync(grantId, ct) is { } existing)
            createdAt = existing.CreatedAt;
        grantId ??= GenerateId();
        await _grants.StoreAsync(grantId, new Grant
        {
            GrantId = grantId,
            ClientId = client.ClientId,
            Subject = subject,
            GrantedScopes = scopes,
            CreatedAt = createdAt,
            ExpiresAt = now + lifetime,
        }, lifetime, ct);

        var value = GenerateId();
        await _tokens.StoreAsync(value, new RefreshToken
        {
            TokenId = value,
            ClientId = client.ClientId,
            Subject = subject,
            Scopes = scopes,
            ExpiresAt = now + lifetime,
            Resources = resources,
            AuthorizationDetailsJson = authorizationDetailsJson,
            GrantId = grantId,
            CnfJwkThumbprint = boundJkt,
            CnfX5tS256 = boundX5t,
        }, lifetime, ct);

        return value;
    }

    /// <summary>
    /// Redeems <paramref name="value"/> exactly once. A second presentation of an already
    /// rotated token revokes the entire family.
    /// </summary>
    public async Task<RotationResult> RotateAsync(
        string value, Client client, string? cnfJwkThumbprint, string? cnfX5tS256, CancellationToken ct)
    {
        var rt = await _tokens.ConsumeAsync(value, ct);
        if (rt is null)
            return new(null, "refresh token not found or already used");

        if (rt.ConsumedAt is not null)
        {
            // Reuse: someone holds a copy of a rotated token. Kill the family and keep the
            // tombstone so later presentations are recognised too.
            if (rt.GrantId is not null)
                await _grants.RemoveAsync(rt.GrantId, ct);
            await StoreTombstoneAsync(value, rt, ct);
            return new(null, "refresh token reuse detected; the grant has been revoked");
        }

        // From here on the token is spent, whatever the outcome.
        await StoreTombstoneAsync(value, rt, ct);

        if (rt.ClientId != client.ClientId)
            return new(null, "client_id mismatch");
        if (rt.ExpiresAt <= DateTimeOffset.UtcNow)
            return new(null, "refresh token expired");
        if (rt.GrantId is not null && await _grants.FindAsync(rt.GrantId, ct) is null)
            return new(null, "the grant for this refresh token has been revoked");

        if (rt.CnfJwkThumbprint is not null && rt.CnfJwkThumbprint != cnfJwkThumbprint)
            return new(null, "refresh token is bound to a different DPoP key");
        if (rt.CnfX5tS256 is not null && rt.CnfX5tS256 != cnfX5tS256)
            return new(null, "refresh token is bound to a different client certificate");

        return new(rt, null);
    }

    /// <summary>Returns the token when it is live (not rotated, expired or revoked); otherwise <c>null</c>.</summary>
    public async Task<RefreshToken?> FindActiveAsync(string value, CancellationToken ct)
    {
        var rt = await _tokens.FindAsync(value, ct);
        if (rt is null || rt.ConsumedAt is not null || rt.ExpiresAt <= DateTimeOffset.UtcNow)
            return null;
        if (rt.GrantId is not null && await _grants.FindAsync(rt.GrantId, ct) is null)
            return null;
        return rt;
    }

    /// <summary>Revokes <paramref name="rt"/> and every token in its rotation family.</summary>
    public async Task RevokeAsync(RefreshToken rt, CancellationToken ct)
    {
        await _tokens.RemoveAsync(rt.TokenId, ct);
        if (rt.GrantId is not null)
            await _grants.RemoveAsync(rt.GrantId, ct);
    }

    private Task StoreTombstoneAsync(string value, RefreshToken rt, CancellationToken ct)
    {
        var remaining = rt.ExpiresAt - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
            return Task.CompletedTask;

        return _tokens.StoreAsync(value, new RefreshToken
        {
            TokenId = rt.TokenId,
            ClientId = rt.ClientId,
            Subject = rt.Subject,
            Scopes = rt.Scopes,
            ExpiresAt = rt.ExpiresAt,
            Resources = rt.Resources,
            AuthorizationDetailsJson = rt.AuthorizationDetailsJson,
            GrantId = rt.GrantId,
            CnfJwkThumbprint = rt.CnfJwkThumbprint,
            CnfX5tS256 = rt.CnfX5tS256,
            ConsumedAt = rt.ConsumedAt ?? DateTimeOffset.UtcNow,
        }, remaining, ct);
    }

    private static string GenerateId() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
