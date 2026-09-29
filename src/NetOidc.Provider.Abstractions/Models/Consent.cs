namespace NetOidc.Provider.Abstractions.Models;

/// <summary>
/// Scopes an End-User has agreed to share with a client. Stored per (client, subject) and
/// consulted before tokens are issued to clients that require consent.
/// </summary>
public sealed class Consent
{
    public required string ClientId { get; init; }

    /// <summary>The End-User's local subject identifier.</summary>
    public required string Subject { get; init; }

    public IReadOnlyList<string> Scopes { get; init; } = [];

    public DateTimeOffset GrantedAt { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Adapter key for a (client, subject) pair.</summary>
    public static string KeyFor(string clientId, string subject) => $"{clientId}\u001f{subject}";
}
