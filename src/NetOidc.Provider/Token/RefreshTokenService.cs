using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Token;

/// <summary>What a refresh token carries forward to the tokens it later produces.</summary>
/// <param name="Subject">The End-User's local subject identifier.</param>
public sealed record RefreshTokenContent(
    string Subject,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> Resources,
    string? AuthorizationDetailsJson = null,
    DateTimeOffset? AuthTime = null,
    string? Acr = null,
    IReadOnlyList<string>? Amr = null,
    string? SessionId = null,
    string? ClaimsRequest = null);

/// <summary>
/// Owns the refresh-token lifecycle: issuance into a grant (rotation family), one-time rotation,
/// reuse detection (OAuth 2.0 Security BCP, RFC 9700 §4.14.2) and sender-constraint checks
/// (RFC 9449 §5, RFC 8705 §4).
/// </summary>
public sealed class RefreshTokenService
{
    private readonly IAdapter<RefreshToken> _tokens;
    private readonly GrantService _grants;
    private readonly IOptions<ProviderOptions> _options;

    public RefreshTokenService(
        IAdapter<RefreshToken> tokens, GrantService grants, IOptions<ProviderOptions> options)
    {
        _tokens = tokens;
        _grants = grants;
        _options = options;
    }

    /// <summary>A refresh token and the grant (rotation family) it belongs to.</summary>
    public sealed record IssuedRefreshToken(string Value, string GrantId);

    /// <summary>Outcome of <see cref="RedeemAsync"/>.</summary>
    /// <param name="Rotated">False when the presented token stays valid (rotation disabled).</param>
    public sealed record RedemptionResult(RefreshToken? Token, string? Error, bool Rotated)
    {
        public bool Succeeded => Token is not null;
    }

    /// <summary>
    /// Issues a refresh token into grant <paramref name="grantId"/>, or into a new grant when
    /// <c>null</c>. Tokens for public clients are bound to the presented DPoP key / client
    /// certificate; confidential clients are constrained by client authentication.
    /// </summary>
    public async Task<IssuedRefreshToken> IssueAsync(
        Client client, RefreshTokenContent content, string? grantId,
        string? cnfJwkThumbprint, string? cnfX5tS256, CancellationToken ct)
    {
        var isPublic = client.TokenEndpointAuthMethod == "none";
        return await StoreAsync(client, content, grantId,
            isPublic ? cnfJwkThumbprint : null, isPublic ? cnfX5tS256 : null, ct);
    }

    /// <summary>
    /// Issues the successor of <paramref name="previous"/> (already validated by
    /// <see cref="RedeemAsync"/>) in the same family, carrying over its binding.
    /// </summary>
    public Task<IssuedRefreshToken> IssueSuccessorAsync(Client client, RefreshToken previous, CancellationToken ct) =>
        StoreAsync(client,
            new RefreshTokenContent(previous.Subject, previous.Scopes, previous.Resources,
                previous.AuthorizationDetailsJson, previous.AuthTime, previous.Acr, previous.Amr,
                previous.SessionId, previous.ClaimsRequest),
            previous.GrantId, previous.CnfJwkThumbprint, previous.CnfX5tS256, ct);

    private async Task<IssuedRefreshToken> StoreAsync(
        Client client, RefreshTokenContent content, string? grantId,
        string? boundJkt, string? boundX5t, CancellationToken ct)
    {
        var lifetime = TimeSpan.FromSeconds(_options.Value.RefreshTokenLifetimeSeconds);

        // Join (and slide) the existing grant, or start a new one.
        if (grantId is null || !await _grants.ExtendAsync(grantId, lifetime, ct))
            grantId = await _grants.CreateAsync(client.ClientId, content.Subject, content.Scopes, lifetime, ct);

        var value = GenerateId();
        await _tokens.StoreAsync(value, new RefreshToken
        {
            TokenId = value,
            ClientId = client.ClientId,
            Subject = content.Subject,
            Scopes = content.Scopes,
            ExpiresAt = DateTimeOffset.UtcNow + lifetime,
            Resources = content.Resources,
            AuthorizationDetailsJson = content.AuthorizationDetailsJson,
            GrantId = grantId,
            CnfJwkThumbprint = boundJkt,
            CnfX5tS256 = boundX5t,
            AuthTime = content.AuthTime,
            Acr = content.Acr,
            Amr = content.Amr,
            SessionId = content.SessionId,
            ClaimsRequest = content.ClaimsRequest,
        }, lifetime, ct);

        return new IssuedRefreshToken(value, grantId);
    }

    /// <summary>
    /// Redeems <paramref name="value"/>. With rotation (the default, and always for public
    /// clients holding unbound tokens) the token is spent exactly once and a second presentation
    /// revokes the entire family. Without rotation the token stays valid.
    /// </summary>
    public async Task<RedemptionResult> RedeemAsync(
        string value, Client client, string? cnfJwkThumbprint, string? cnfX5tS256, CancellationToken ct)
    {
        var existing = await _tokens.FindAsync(value, ct);
        if (existing is null)
            return new(null, "refresh token not found or already used", false);

        // RFC 9700 §4.14.2: rotation is mandatory unless the token is sender-constrained or the
        // client is confidential.
        var mustRotate = _options.Value.RotateRefreshTokens ||
            (client.TokenEndpointAuthMethod == "none" &&
             existing.CnfJwkThumbprint is null && existing.CnfX5tS256 is null);

        RefreshToken? rt;
        if (mustRotate)
        {
            rt = await _tokens.ConsumeAsync(value, ct);
            if (rt is null)
                return new(null, "refresh token not found or already used", true);

            if (rt.ConsumedAt is not null)
            {
                // Reuse: someone holds a copy of a rotated token. Kill the family and keep the
                // tombstone so later presentations are recognised too.
                if (rt.GrantId is not null)
                    await _grants.RevokeAsync(rt.GrantId, ct);
                await StoreTombstoneAsync(value, rt, ct);
                return new(null, "refresh token reuse detected; the grant has been revoked", true);
            }

            // From here on the token is spent, whatever the outcome.
            await StoreTombstoneAsync(value, rt, ct);
        }
        else
        {
            rt = existing;
            if (rt.ConsumedAt is not null)
                return new(null, "refresh token not found or already used", false);
        }

        if (rt.ClientId != client.ClientId)
            return new(null, "client_id mismatch", mustRotate);
        if (rt.ExpiresAt <= DateTimeOffset.UtcNow)
            return new(null, "refresh token expired", mustRotate);
        if (rt.GrantId is not null && !await _grants.IsActiveAsync(rt.GrantId, ct))
            return new(null, "the grant for this refresh token has been revoked", mustRotate);

        if (rt.CnfJwkThumbprint is not null && rt.CnfJwkThumbprint != cnfJwkThumbprint)
            return new(null, "refresh token is bound to a different DPoP key", mustRotate);
        if (rt.CnfX5tS256 is not null && rt.CnfX5tS256 != cnfX5tS256)
            return new(null, "refresh token is bound to a different client certificate", mustRotate);

        return new(rt, null, mustRotate);
    }

    /// <summary>Returns the token when it is live (not rotated, expired or revoked); otherwise <c>null</c>.</summary>
    public async Task<RefreshToken?> FindActiveAsync(string value, CancellationToken ct)
    {
        var rt = await _tokens.FindAsync(value, ct);
        if (rt is null || rt.ConsumedAt is not null || rt.ExpiresAt <= DateTimeOffset.UtcNow)
            return null;
        if (rt.GrantId is not null && !await _grants.IsActiveAsync(rt.GrantId, ct))
            return null;
        return rt;
    }

    /// <summary>Revokes <paramref name="rt"/> and every token in its grant.</summary>
    public async Task RevokeAsync(RefreshToken rt, CancellationToken ct)
    {
        await _tokens.RemoveAsync(rt.TokenId, ct);
        if (rt.GrantId is not null)
            await _grants.RevokeAsync(rt.GrantId, ct);
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
            AuthTime = rt.AuthTime,
            Acr = rt.Acr,
            Amr = rt.Amr,
            SessionId = rt.SessionId,
            ClaimsRequest = rt.ClaimsRequest,
            ConsumedAt = rt.ConsumedAt ?? DateTimeOffset.UtcNow,
        }, remaining, ct);
    }

    private static string GenerateId() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
