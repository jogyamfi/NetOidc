namespace NetOidc.Provider.Abstractions.Models;

/// <summary>Refresh token stored per grant. Consumed and rotated on each use.</summary>
public sealed class RefreshToken
{
    public required string TokenId { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
    public required DateTimeOffset ExpiresAt { get; init; }
}
