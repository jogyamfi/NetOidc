namespace NetOidc.Provider.Abstractions.Models;

/// <summary>
/// Tracks an authenticated user-agent session.
/// A session is created when an authorization response is issued and
/// used to drive RP-initiated and back-channel logout.
/// </summary>
public sealed class Session
{
    /// <summary>Opaque session identifier (<c>sid</c> claim in ID tokens / logout tokens).</summary>
    public required string SessionId { get; init; }

    public required string Subject { get; init; }

    /// <summary>Client IDs that have received tokens in this session.</summary>
    public IReadOnlyList<string> ClientIds { get; init; } = [];

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? ExpiresAt { get; init; }
}
