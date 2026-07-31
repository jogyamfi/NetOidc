namespace NetOidc.Provider.Abstractions.Models;

public enum TokenFormat { Jwt, Opaque }

/// <summary>One issued access token derived from a Grant.</summary>
public sealed class AccessToken
{
    public required string TokenId { get; init; }

    public required string GrantId { get; init; }

    public required string ClientId { get; init; }

    /// <summary>Null for client_credentials tokens with no user context.</summary>
    public string? Subject { get; init; }

    public IReadOnlyList<string> Scopes { get; init; } = [];

    public TokenFormat Format { get; init; } = TokenFormat.Jwt;

    public DateTimeOffset ExpiresAt { get; init; }

    // ── Phase 4 ──────────────────────────────────────────────────────────────

    /// <summary>Resource indicator bound to this token (RFC 8707).</summary>
    public string? Resource { get; init; }

    /// <summary>JSON-encoded <c>authorization_details</c> array (RFC 9396).</summary>
    public string? AuthorizationDetailsJson { get; init; }
}
