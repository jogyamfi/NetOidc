using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Configuration;

/// <summary>All top-level configuration knobs for the provider.</summary>
public sealed class ProviderOptions
{
    /// <summary>Authorization server issuer URI (e.g. https://auth.example.com).</summary>
    public string Issuer { get; set; } = string.Empty;

    // -- Endpoint paths --

    public string DiscoveryEndpoint { get; set; } = "/.well-known/openid-configuration";
    public string JwksEndpoint { get; set; } = "/.well-known/jwks.json";
    public string AuthorizationEndpoint { get; set; } = "/connect/authorize";
    public string TokenEndpoint { get; set; } = "/connect/token";
    public string UserInfoEndpoint { get; set; } = "/connect/userinfo";
    public string IntrospectionEndpoint { get; set; } = "/connect/introspect";
    public string RevocationEndpoint { get; set; } = "/connect/revoke";
    public string EndSessionEndpoint { get; set; } = "/connect/end_session";

    // -- DCR (RFC 7591 / RFC 7592) --

    /// <summary>When true, <c>POST /connect/register</c> is active.</summary>
    public bool DcrEnabled { get; set; } = false;

    public string RegistrationEndpoint { get; set; } = "/connect/register";

    /// <summary>
    /// When set, every registration request must carry this value as a Bearer token.
    /// Set to <c>null</c> to allow open registration.
    /// </summary>
    public string? InitialAccessToken { get; set; }

    /// <summary>
    /// When true, the registration_access_token is rotated on every PUT (update) request.
    /// </summary>
    public bool DcrRotateRegistrationTokens { get; set; } = false;

    /// <summary>
    /// Lifetime in seconds of dynamically issued client_secrets; 0 = non-expiring.
    /// </summary>
    public int ClientSecretLifetimeSeconds { get; set; } = 0;

    /// <summary>
    /// Optional hook called after client metadata is built. Throw to reject registration.
    /// </summary>
    public Func<Abstractions.Models.Client, CancellationToken, Task>? ValidateDynamicClient { get; set; }

    // -- Logout / Session --

    /// <summary>
    /// When true, the end_session endpoint is active and OIDC sessions are tracked.
    /// </summary>
    public bool LogoutEnabled { get; set; } = false;

    /// <summary>
    /// When true (and <see cref="LogoutEnabled"/> is true), back-channel logout tokens
    /// are sent to clients that have a <c>backchannel_logout_uri</c> registered.
    /// </summary>
    public bool BackChannelLogoutEnabled { get; set; } = false;

    /// <summary>Lifetime in seconds of back-channel logout tokens (default 120 s).</summary>
    public int LogoutTokenLifetimeSeconds { get; set; } = 120;

    // -- Interaction --

    /// <summary>Path the provider redirects to when the user is not authenticated.</summary>
    public string LoginPath { get; set; } = "/account/login";

    // -- Static configuration --

    public IList<Client> StaticClients { get; set; } = [];

    public IList<Scope> Scopes { get; set; } = [new Scope { Name = "openid" }];

    // -- Token lifetimes (seconds) --

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeSeconds { get; set; } = 86400;
    public int IdTokenLifetimeSeconds { get; set; } = 3600;
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 60;

    /// <summary>Issue refresh tokens alongside access tokens for authorization_code grants.</summary>
    public bool IssueRefreshTokens { get; set; } = true;

    // -- Subject identifier types (OIDC Core §8) --

    /// <summary>"public" (default) or "pairwise" (OIDC Core §8.1).</summary>
    public string SubjectType { get; set; } = "public";

    /// <summary>
    /// Secret used to compute pairwise sub identifiers. Required when <see cref="SubjectType"/>
    /// is "pairwise". Defaults to a value derived from <see cref="Issuer"/> if unset.
    /// </summary>
    public string? PairwiseSalt { get; set; }

    // -- RFC 9207 Authorization Server Issuer Identification --

    /// <summary>
    /// When true, the <c>iss</c> parameter is added to every authorization response
    /// (RFC 9207). Enabled by default.
    /// </summary>
    public bool IssuerIdentificationEnabled { get; set; } = true;

    // -- RFC 8252 OAuth 2.0 for Native Apps --

    /// <summary>
    /// When true, loopback redirect URIs (localhost/127.0.0.1/::1) are matched by
    /// host+path only, ignoring the port (RFC 8252 §7.3). Enabled by default.
    /// </summary>
    public bool AllowNativeAppRedirects { get; set; } = true;

    // -- Claim sourcing --

    /// <summary>
    /// Called by the UserInfo endpoint to load profile claims for a subject.
    /// The second argument is the list of granted scopes. Default returns only sub.
    /// </summary>
    public Func<string, IReadOnlyList<string>, CancellationToken, Task<IReadOnlyDictionary<string, object>>>
        FindUserClaims { get; set; } =
            static (sub, _, _) => Task.FromResult<IReadOnlyDictionary<string, object>>(
                new Dictionary<string, object> { ["sub"] = sub });

    // ── PAR — Pushed Authorization Requests (RFC 9126) ───────────────────────

    /// <summary>When true, the <c>POST /connect/par</c> endpoint is active.</summary>
    public bool PushedAuthorizationEnabled { get; set; } = false;

    /// <summary>When true, every authorization request must be a previously pushed request.</summary>
    public bool RequirePushedAuthorization { get; set; } = false;

    public string PushedAuthorizationEndpoint { get; set; } = "/connect/par";

    /// <summary>Lifetime in seconds of PAR request objects (default 90 s per RFC 9126 §2.2).</summary>
    public int PushedAuthorizationLifetimeSeconds { get; set; } = 90;

    // ── JAR — JWT-Secured Authorization Requests (RFC 9101) ──────────────────

    /// <summary>
    /// When true, the provider processes <c>request</c> JWT parameters on the authorization endpoint.
    /// </summary>
    public bool JarEnabled { get; set; } = false;

    /// <summary>
    /// When true (and <see cref="JarEnabled"/> is true), every authorization request must include a
    /// signed request object; unsigned (alg=none) objects are rejected.
    /// </summary>
    public bool JarRequireSignedRequestObject { get; set; } = false;

    // ── JARM — JWT Authorization Response Mode ───────────────────────────────

    /// <summary>
    /// When true, the <c>query.jwt</c>, <c>fragment.jwt</c>, and <c>form_post.jwt</c> response modes
    /// are available (JWT Authorization Response Mode).
    /// </summary>
    public bool JarmEnabled { get; set; } = false;

    // ── Resource Indicators (RFC 8707) ───────────────────────────────────────

    /// <summary>When true, the <c>resource</c> parameter is accepted and stored with tokens.</summary>
    public bool ResourceIndicatorsEnabled { get; set; } = false;

    // ── Rich Authorization Requests (RFC 9396) ───────────────────────────────

    /// <summary>When true, the <c>authorization_details</c> parameter is processed.</summary>
    public bool RichAuthorizationRequestsEnabled { get; set; } = false;

    /// <summary>
    /// Authorization details types this server supports (advertised in discovery).
    /// Empty means no restriction on types.
    /// </summary>
    public IList<string> AuthorizationDetailsTypesSupported { get; set; } = [];

    // ── Token Exchange (RFC 8693) ─────────────────────────────────────────────

    /// <summary>When true, the <c>urn:ietf:params:oauth:grant-type:token-exchange</c> grant is active.</summary>
    public bool TokenExchangeEnabled { get; set; } = false;

    // ── JWT Bearer grant (RFC 7523) ───────────────────────────────────────────

    /// <summary>When true, the <c>urn:ietf:params:oauth:grant-type:jwt-bearer</c> grant is active.</summary>
    public bool JwtBearerGrantEnabled { get; set; } = false;

    // ── Phase 5 — DPoP (RFC 9449) ────────────────────────────────────────────

    /// <summary>
    /// When true, the token endpoint accepts a <c>DPoP</c> header and issues
    /// DPoP-bound access tokens.  DPoP proofs are also validated on the UserInfo endpoint.
    /// </summary>
    public bool DPoPEnabled { get; set; } = false;

    /// <summary>Allowed IAT drift for DPoP proofs in seconds (default 300 = 5 min).</summary>
    public int DPoPProofLifetimeSeconds { get; set; } = 300;

    // ── Phase 5 — Mutual TLS (RFC 8705) ──────────────────────────────────────

    /// <summary>
    /// When true, <c>tls_client_auth</c> and <c>self_signed_tls_client_auth</c>
    /// are accepted as token-endpoint auth methods and mTLS-bound tokens may be issued.
    /// </summary>
    public bool MtlsEnabled { get; set; } = false;

    /// <summary>
    /// Optional HTTP header name from which a PEM-encoded client certificate is read
    /// (for reverse-proxy / test scenarios).  When null, <c>IConnectionFeature</c> is used.
    /// Example: <c>"X-Client-Cert"</c>.
    /// </summary>
    public string? MtlsClientCertificateHeader { get; set; }

    // ── Phase 6 — Device Authorization Grant (RFC 8628) ──────────────────────

    /// <summary>When true, the device authorization endpoint is active.</summary>
    public bool DeviceFlowEnabled { get; set; } = false;

    public string DeviceAuthorizationEndpoint { get; set; } = "/connect/device_authorization";

    /// <summary>
    /// URI where the user enters the <c>user_code</c> to authorize a device.
    /// Advertised as <c>verification_uri</c> in the device authorization response.
    /// </summary>
    public string DeviceVerificationUri { get; set; } = "/connect/device";

    /// <summary>Lifetime in seconds of device codes (default 600 s per RFC 8628 §3.2).</summary>
    public int DeviceCodeLifetimeSeconds { get; set; } = 600;

    /// <summary>
    /// Minimum polling interval in seconds for the device_code grant (default 5 s per RFC 8628 §3.5).
    /// </summary>
    public int DevicePollingIntervalSeconds { get; set; } = 5;

    // ── Phase 6 — CIBA (OpenID CIBA Core 1.0) ────────────────────────────────

    /// <summary>When true, the backchannel authentication endpoint is active (poll mode).</summary>
    public bool CibaEnabled { get; set; } = false;

    public string BackchannelAuthenticationEndpoint { get; set; } = "/connect/ciba";

    /// <summary>Lifetime in seconds of <c>auth_req_id</c> tokens (default 120 s).</summary>
    public int CibaAuthReqIdLifetimeSeconds { get; set; } = 120;

    /// <summary>Minimum polling interval in seconds for the CIBA poll mode (default 5 s).</summary>
    public int CibaPollingIntervalSeconds { get; set; } = 5;

    /// <summary>
    /// Hook called after a CIBA request is accepted. The implementation should trigger
    /// out-of-band authentication and later call the provider's
    /// <see cref="CompleteCibaRequestAsync"/> method to approve or deny the request.
    /// </summary>
    public Func<Abstractions.Models.BackchannelAuthenticationRequest, CancellationToken, Task>?
        ProcessBackchannelAuthenticationRequest { get; set; }

    // ── Phase 7 — FAPI Profiles ───────────────────────────────────────────────

    /// <summary>
    /// FAPI compliance profile to enforce at runtime (response_type, auth method,
    /// PKCE, PAR, JARM constraints). Defaults to <see cref="FapiProfile.None"/>.
    /// </summary>
    public FapiProfile FapiProfile { get; set; } = FapiProfile.None;

    /// <summary>
    /// When true, the provider validates the full <see cref="ProviderOptions"/> graph
    /// against the selected <see cref="FapiProfile"/> at startup and rejects invalid
    /// configuration before the first request is served.
    /// </summary>
    public bool FapiProfileValidationEnabled { get; set; } = false;

    // ── Phase 8 — OpenID Federation 1.1 ──────────────────────────────────────

    /// <summary>
    /// When true, the provider publishes its entity configuration at
    /// <c>/.well-known/openid-federation</c> (OpenID Federation 1.1 §6).
    /// </summary>
    public bool FederationEnabled { get; set; } = false;

    /// <summary>
    /// Authority hints: entity identifiers of trust anchors or intermediate entities
    /// that know about this OP. Advertised in the entity configuration.
    /// </summary>
    public IList<string> FederationAuthorityHints { get; set; } = [];

    /// <summary>Lifetime in seconds of entity statements (default 86400 = 24 h).</summary>
    public int FederationEntityStatementLifetimeSeconds { get; set; } = 86400;

    // ── Phase 8 — OpenID for Verifiable Credential Issuance 1.0 ──────────────

    /// <summary>
    /// When true, the <c>/.well-known/openid-credential-issuer</c> metadata endpoint,
    /// credential endpoint, and nonce endpoint are active.
    /// </summary>
    public bool VciEnabled { get; set; } = false;

    /// <summary>
    /// Credential issuer entity identifier URL. Defaults to <see cref="Issuer"/> when empty.
    /// Override when the credential issuer is a distinct entity from the authorization server.
    /// </summary>
    public string VciCredentialIssuer { get; set; } = string.Empty;

    public string VciCredentialEndpoint { get; set; } = "/connect/credential";

    /// <summary>c_nonce endpoint path (OID4VCI 1.0 §8.2).</summary>
    public string VciNonceEndpoint { get; set; } = "/connect/nonce";

    /// <summary>Lifetime in seconds of issued c_nonce values (default 300 s).</summary>
    public int VciNonceLifetimeSeconds { get; set; } = 300;

    /// <summary>
    /// Credential types the issuer supports, keyed by <c>credential_configuration_id</c>.
    /// Advertised in the <c>credential_configurations_supported</c> map of the issuer metadata.
    /// </summary>
    public IList<Vci.CredentialConfiguration> VciCredentialConfigurations { get; set; } = [];

    /// <summary>
    /// Hook invoked to issue a verifiable credential.
    /// Arguments: (subject, credentialConfigurationId, cancellationToken).
    /// Must return the credential as a string (JWT-VC, SD-JWT, etc.).
    /// </summary>
    public Func<string, string, CancellationToken, Task<string>>? IssueCredential { get; set; }

    // ── Phase 8 — CORS ─────────────────────────────────────────────────────────

    /// <summary>When true, CORS headers are applied to OIDC provider endpoints.</summary>
    public bool CorsEnabled { get; set; } = false;

    /// <summary>
    /// Allowed CORS origins. An empty list (while <see cref="CorsEnabled"/> is true)
    /// allows all origins (<c>*</c>).
    /// </summary>
    public IList<string> CorsAllowedOrigins { get; set; } = [];

    // ── Phase 8 — Client ID Metadata Document (draft) ─────────────────────────

    /// <summary>
    /// When true, a client whose <c>client_id</c> is a URL may omit pre-registration;
    /// the provider fetches the Client ID Metadata Document from that URL on first use.
    /// </summary>
    public bool ClientIdMetadataDocumentEnabled { get; set; } = false;
}
