namespace NetOidc.Provider.Abstractions.Models;

/// <summary>Canonical record of what a subject authorized for a client.</summary>
public sealed class Grant
{
    public required string GrantId { get; init; }

    public required string ClientId { get; init; }

    public required string Subject { get; init; }

    public IReadOnlyList<string> GrantedScopes { get; init; } = [];

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? ExpiresAt { get; init; }
}
