namespace NetOidc.Provider.Abstractions.Models;

/// <summary>One-time-use authorization code issued by the authorization endpoint.</summary>
public sealed class AuthorizationCode
{
    public required string Code { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Subject { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
    public string? Nonce { get; init; }
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
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
}
