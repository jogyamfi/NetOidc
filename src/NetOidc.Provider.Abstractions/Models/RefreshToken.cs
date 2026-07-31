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
}
