namespace NetOidc.Provider.Abstractions.Models;

/// <summary>Refresh token stored per grant. Consumed and rotated on each use.</summary>
public sealed class RefreshToken
{
    public required string TokenId { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
    public required DateTimeOffset ExpiresAt { get; init; }

    // ── Phase 4 ──────────────────────────────────────────────────────────────

    /// <summary>Resource indicators from the originating authorization request (RFC 8707).</summary>
    public IReadOnlyList<string> Resources { get; init; } = [];

    /// <summary>JSON-encoded <c>authorization_details</c> array (RFC 9396).</summary>
    public string? AuthorizationDetailsJson { get; init; }

    // ── Rotation & sender constraint ─────────────────────────────────────────

    /// <summary>
    /// Identifies the rotation family (a <see cref="Grant"/>). Every token produced by
    /// rotating this one shares the id; detecting reuse revokes the whole family.
    /// </summary>
    public string? GrantId { get; init; }

    /// <summary>
    /// Set when the token has been rotated. The record is kept as a tombstone until it
    /// expires so that a second presentation can be recognised as reuse.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; init; }

    /// <summary>DPoP key thumbprint the token is bound to (RFC 9449 §5), or <c>null</c>.</summary>
    public string? CnfJwkThumbprint { get; init; }

    /// <summary>Client certificate thumbprint the token is bound to (RFC 8705 §4), or <c>null</c>.</summary>
    public string? CnfX5tS256 { get; init; }
}
