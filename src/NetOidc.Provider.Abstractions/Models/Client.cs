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

    // ── JAR (RFC 9101) — JWT-Secured Authorization Requests ─────────────────

    /// <summary>Inline JWKS JSON used to verify the client's signed request objects.</summary>
    public string? JwksJson { get; init; }

    /// <summary>Expected signing alg for request objects (e.g. "RS256"). Null = any supported alg.</summary>
    public string? RequestObjectSigningAlg { get; init; }

    /// <summary>When true, every authorization request to this client must include a signed request object.</summary>
    public bool RequireSignedRequestObject { get; init; } = false;

    /// <summary>Alg used to encrypt incoming request objects sent to the OP (e.g. "RSA-OAEP").</summary>
    public string? RequestObjectEncryptionAlg { get; init; }

    /// <summary>Enc used to encrypt incoming request objects (e.g. "A256GCM").</summary>
    public string? RequestObjectEncryptionEnc { get; init; }

    // ── JARM — JWT Authorization Response Mode ───────────────────────────────

    /// <summary>Signing alg for JARM authorization responses (e.g. "RS256"). Null = use server default.</summary>
    public string? AuthorizationSignedResponseAlg { get; init; }

    // ── ID Token encryption ──────────────────────────────────────────────────

    /// <summary>Key-wrapping alg for encrypted id_tokens sent to this client (e.g. "RSA-OAEP").</summary>
    public string? IdTokenEncryptedResponseAlg { get; init; }

    /// <summary>Content encryption alg for encrypted id_tokens (e.g. "A256GCM").</summary>
    public string? IdTokenEncryptedResponseEnc { get; init; }

    // ── Phase 5 — Private-key JWT client auth (RFC 7523) ─────────────────────

    /// <summary>
    /// Inline JWKS JSON used to verify <c>private_key_jwt</c> client assertions.
    /// Overlaps with <see cref="JwksJson"/> (JAR); the same field is re-used.
    /// </summary>
    // JwksJson already declared above; no new field needed for private_key_jwt.

    // ── Phase 5 — mTLS client auth (RFC 8705) ────────────────────────────────

    /// <summary>Expected subject DN when <c>token_endpoint_auth_method</c> is <c>tls_client_auth</c>.</summary>
    public string? TlsClientAuthSubjectDn { get; init; }

    /// <summary>Expected SAN DNS name for <c>tls_client_auth</c>.</summary>
    public string? TlsClientAuthSanDns { get; init; }

    /// <summary>Expected SAN URI for <c>tls_client_auth</c>.</summary>
    public string? TlsClientAuthSanUri { get; init; }

    /// <summary>Expected SAN IP address for <c>tls_client_auth</c>.</summary>
    public string? TlsClientAuthSanIp { get; init; }

    /// <summary>
    /// When true, tokens issued to this client carry a <c>cnf.x5t#S256</c> claim binding
    /// them to the mTLS certificate presented during authentication (RFC 8705 §3).
    /// </summary>
    public bool UseMtlsBoundTokens { get; init; } = false;

    // ── Phase 6 — CIBA (OpenID CIBA Core 1.0) ────────────────────────────────

    /// <summary>
    /// CIBA delivery mode for this client: "poll", "ping", or "push".
    /// Null means CIBA is not enabled for this client.
    /// </summary>
    public string? CibaDeliveryMode { get; init; }

    /// <summary>
    /// URI to which the OP sends a notification when CIBA authorization completes
    /// (required for "ping" and "push" modes).
    /// </summary>
    public string? CibaClientNotificationEndpoint { get; init; }

    /// <summary>
    /// Required for "ping" and "push" modes — the JWK Set used to encrypt
    /// the push notification token sent to the client notification endpoint.
    /// </summary>
    public string? CibaJwksJson { get; init; }
}
