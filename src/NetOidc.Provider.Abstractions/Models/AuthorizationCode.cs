namespace NetOidc.Provider.Abstractions.Models;

/// <summary>One-time-use authorization code issued by the authorization endpoint.</summary>
public sealed class AuthorizationCode
{
    public required string Code { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }

    /// <summary>
    /// True when <see cref="RedirectUri"/> was sent in the authorization request (rather than
    /// defaulted from the client's single registered URI). The token request must then repeat
    /// it exactly (RFC 6749 §4.1.3).
    /// </summary>
    public bool RedirectUriInRequest { get; init; }

    /// <summary>
    /// The End-User's local subject identifier. Pairwise identifiers (OIDC Core §8) are derived
    /// from it only when tokens are issued.
    /// </summary>
    public required string Subject { get; init; }

    public IReadOnlyList<string> Scopes { get; init; } = [];
    public string? Nonce { get; init; }
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }

    /// <summary>
    /// JWK thumbprint the code is bound to (<c>dpop_jkt</c>, RFC 9449 §10): the token request
    /// must carry a DPoP proof signed with that key.
    /// </summary>
    public string? DPoPJkt { get; init; }

    /// <summary>When the End-User actually authenticated (OIDC Core §2 <c>auth_time</c>).</summary>
    public required DateTimeOffset AuthTime { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Raw JSON value of the OIDC 'claims' request parameter (OIDC Core §5.5).</summary>
    public string? ClaimsRequest { get; init; }

    /// <summary>Authentication Context Reference asserted by the interaction service.</summary>
    public string? Acr { get; init; }

    /// <summary>Authentication Methods References asserted by the interaction service.</summary>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>OIDC session ID — included in ID tokens as the <c>sid</c> claim when set.</summary>
    public string? SessionId { get; init; }

    // ── Phase 4 ──────────────────────────────────────────────────────────────

    /// <summary>Resource indicators requested via <c>resource</c> parameter (RFC 8707).</summary>
    public IReadOnlyList<string> Resources { get; init; } = [];

    /// <summary>JSON-encoded <c>authorization_details</c> array (RFC 9396).</summary>
    public string? AuthorizationDetailsJson { get; init; }

    // ── Grant lineage ────────────────────────────────────────────────────────

    /// <summary>
    /// The <see cref="Grant"/> this code belongs to. Tokens issued from the code join the
    /// same grant, so replaying the code can revoke them all (RFC 6749 §4.1.2).
    /// </summary>
    public string? GrantId { get; init; }

    /// <summary>Set once the code has been redeemed; the record is kept as a replay tombstone.</summary>
    public DateTimeOffset? ConsumedAt { get; init; }
}
