namespace NetOidc.Provider.Abstractions.Models;

/// <summary>Registered OAuth2/OIDC client (relying party).</summary>
public sealed class Client
{
    public required string ClientId { get; init; }

    public string? ClientSecret { get; init; }

    public IReadOnlyList<string> RedirectUris { get; init; } = [];

    public IReadOnlyList<string> AllowedGrantTypes { get; init; } = [];

    public IReadOnlyList<string> AllowedScopes { get; init; } = [];

    /// <summary>RFC 7591 token_endpoint_auth_method.</summary>
    public string TokenEndpointAuthMethod { get; init; } = "client_secret_basic";

    public bool RequirePkce { get; init; } = true;

    // ── DCR fields (RFC 7591 / OIDC Registration) ───────────────────────────

    /// <summary>True when this client was dynamically registered via DCR.</summary>
    public bool IsDynamic { get; init; } = false;

    /// <summary>SHA-256 hex digest of the registration access token (RFC 7592).</summary>
    public string? RegistrationAccessTokenHash { get; init; }

    /// <summary>Unix timestamp of when the client_id was issued.</summary>
    public long ClientIdIssuedAt { get; init; }

    /// <summary>Unix timestamp when the client_secret expires; 0 means non-expiring.</summary>
    public long ClientSecretExpiresAt { get; init; }

    // ── OIDC Registration display / contact metadata ─────────────────────────

    public string? ClientName { get; init; }

    public string? ClientUri { get; init; }

    public string? LogoUri { get; init; }

    public IReadOnlyList<string> Contacts { get; init; } = [];

    // ── Session / Logout metadata (OIDC Back-Channel Logout §2) ─────────────

    /// <summary>URI to which the OP sends back-channel logout tokens.</summary>
    public string? BackChannelLogoutUri { get; init; }

    /// <summary>Whether the OP must include a <c>sid</c> claim in logout tokens.</summary>
    public bool BackChannelLogoutSessionRequired { get; init; } = false;

    /// <summary>Allowed URIs to redirect to after RP-initiated logout.</summary>
    public IReadOnlyList<string> PostLogoutRedirectUris { get; init; } = [];
}
