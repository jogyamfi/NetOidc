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

    // ── Phase 5 ──────────────────────────────────────────────────────────────

    /// <summary>
    /// DPoP JWK thumbprint bound to this token (<c>cnf.jkt</c>, RFC 9449).
    /// Non-null when the token was issued in response to a DPoP-protected token request.
    /// </summary>
    public string? CnfJwkThumbprint { get; init; }

    /// <summary>
    /// mTLS certificate thumbprint bound to this token (<c>cnf.x5t#S256</c>, RFC 8705).
    /// Non-null when the token was issued to a client that authenticated via mTLS.
    /// </summary>
    public string? CnfX5tS256 { get; init; }
}
