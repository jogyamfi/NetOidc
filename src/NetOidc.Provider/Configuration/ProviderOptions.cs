using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Configuration;

/// <summary>All top-level configuration knobs for the provider.</summary>
public sealed class ProviderOptions
{
    /// <summary>Authorization server issuer URI (e.g. https://auth.example.com).</summary>
    public string Issuer { get; set; } = string.Empty;

    // -- Keys --

    /// <summary>
    /// Signing and encryption keys (see <c>NetOidcBuilder.AddSigningKey</c>). When empty, keys
    /// are generated at startup — development only: a Production host refuses to start.
    /// </summary>
    public IList<Jose.ProviderKey> Keys { get; set; } = [];

    /// <summary>Algorithm used when a client registered none (default RS256).</summary>
    public string DefaultSigningAlgorithm { get; set; } = "RS256";

    // -- Endpoint paths --

    public string DiscoveryEndpoint { get; set; } = "/.well-known/openid-configuration";
    public string JwksEndpoint { get; set; } = "/.well-known/jwks.json";
    public string AuthorizationEndpoint { get; set; } = "/connect/authorize";
    public string TokenEndpoint { get; set; } = "/connect/token";
    public string UserInfoEndpoint { get; set; } = "/connect/userinfo";
    public string IntrospectionEndpoint { get; set; } = "/connect/introspect";
    public string RevocationEndpoint { get; set; } = "/connect/revoke";
    public string EndSessionEndpoint { get; set; } = "/connect/end_session";

    /// <summary>
    /// Decides whether a client may introspect an access token that was neither issued to it
    /// nor addressed to it (<c>aud</c>). Use this to authorise resource servers. When
    /// <c>null</c>, such requests report <c>{"active":false}</c>.
    /// </summary>
    public Func<IntrospectionContext, CancellationToken, Task<bool>>? AuthorizeIntrospection { get; set; }

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

    /// <summary>
    /// Grant types a dynamically registered client may request. Anything else is rejected
    /// with <c>invalid_client_metadata</c>. Add e.g. <c>client_credentials</c> deliberately.
    /// </summary>
    public IList<string> DcrAllowedGrantTypes { get; set; } = ["authorization_code", "refresh_token"];

    /// <summary>
    /// When <c>true</c>, dynamically registered clients may point server-called URLs
    /// (<c>backchannel_logout_uri</c>) at private, loopback or plain-http addresses.
    /// Leave <c>false</c> in production: those URLs are otherwise an SSRF vector.
    /// </summary>
    public bool DcrAllowPrivateNetworkUris { get; set; } = false;

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

    /// <summary>
    /// Page that asks the End-User to confirm a logout that did not carry a valid
    /// <c>id_token_hint</c> (RP-Initiated Logout §2). It receives the original request
    /// parameters and must POST them back to the end-session endpoint with <c>confirm=true</c>
    /// and an antiforgery token.
    /// </summary>
    public string LogoutConfirmationPath { get; set; } = "/account/logout";

    /// <summary>Sliding lifetime in seconds of an OIDC session (default 14 days).</summary>
    public int SessionLifetimeSeconds { get; set; } = 14 * 24 * 3600;

    /// <summary>
    /// When true (and <see cref="LogoutEnabled"/> is true), logout renders iframes to clients'
    /// <c>frontchannel_logout_uri</c> (OIDC Front-Channel Logout 1.0).
    /// </summary>
    public bool FrontChannelLogoutEnabled { get; set; } = false;

    // -- Interaction --

    /// <summary>Path the provider redirects to when the user is not authenticated.</summary>
    public string LoginPath { get; set; } = "/account/login";

    /// <summary>
    /// Renders errors that cannot be returned to the client — an unknown <c>client_id</c> or an
    /// unregistered <c>redirect_uri</c> at the authorization endpoint, or an invalid logout
    /// request — as a page for the End-User. When <c>null</c> a JSON error body is returned.
    /// </summary>
    public Func<Microsoft.AspNetCore.Http.HttpContext, Errors.OAuthError, Task<Microsoft.AspNetCore.Http.IResult>>? RenderErrorPage { get; set; }

    /// <summary>
    /// Path the provider redirects to when the End-User must consent. The page receives
    /// <c>client_id</c>, <c>scope</c> and <c>returnUrl</c>, records consent with
    /// <see cref="Interaction.ConsentService"/> and then redirects to <c>returnUrl</c>.
    /// </summary>
    public string ConsentPath { get; set; } = "/account/consent";

    /// <summary>Lifetime in seconds of a suspended authorization request awaiting login/consent (default 600).</summary>
    public int InteractionLifetimeSeconds { get; set; } = 600;

    // -- Static configuration --

    public IList<Client> StaticClients { get; set; } = [];

    public IList<Scope> Scopes { get; set; } = [new Scope { Name = "openid" }];

    // -- Token lifetimes (seconds) --

    /// <summary>
    /// Default access-token format. <c>Jwt</c> (RFC 9068) can be validated by resource servers
    /// locally; <c>Opaque</c> tokens are random references that must be introspected, which makes
    /// revocation immediate and keeps token contents private. Clients may override it.
    /// </summary>
    public Abstractions.Models.TokenFormat AccessTokenFormat { get; set; } = Abstractions.Models.TokenFormat.Jwt;

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeSeconds { get; set; } = 86400;
    public int IdTokenLifetimeSeconds { get; set; } = 3600;
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 60;

    /// <summary>Issue refresh tokens alongside access tokens for authorization_code grants.</summary>
    public bool IssueRefreshTokens { get; set; } = true;

    /// <summary>
    /// Rotate refresh tokens on every use (default). When false, confidential clients and
    /// sender-constrained tokens keep their refresh token; unbound public-client tokens always rotate.
    /// </summary>
    public bool RotateRefreshTokens { get; set; } = true;

    /// <summary>
    /// Accept <c>code_challenge_method=plain</c> (and a missing method, which RFC 7636 treats as
    /// plain). Off by default: only S256 is accepted.
    /// </summary>
    public bool AllowPlainPkce { get; set; } = false;

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
    /// Loads End-User claims for the UserInfo endpoint and ID tokens. The request carries the
    /// local subject and the claim names that may be released; claims outside
    /// <see cref="Claims.UserClaimsRequest.ClaimNames"/> are dropped. Default returns nothing.
    /// </summary>
    public Func<Claims.UserClaimsRequest, CancellationToken, Task<IReadOnlyDictionary<string, object>>>
        FindUserClaims { get; set; } =
            static (_, _) => Task.FromResult<IReadOnlyDictionary<string, object>>(
                new Dictionary<string, object>());

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

    /// <summary>
    /// Resource indicators (absolute URIs) clients may request (RFC 8707 §2). Requests for any
    /// other resource fail with <c>invalid_target</c>.
    /// </summary>
    public IList<string> AllowedResources { get; set; } = [];

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

    /// <summary>
    /// Decides whether a token exchange may proceed. When <c>null</c>, a client may only
    /// exchange subject tokens that were issued to itself. Scopes are always bounded by the
    /// subject token and the client's allowed scopes, regardless of this policy.
    /// </summary>
    public Func<TokenExchangeContext, CancellationToken, Task<bool>>? AuthorizeTokenExchange { get; set; }

    // ── JWT Bearer grant (RFC 7523) ───────────────────────────────────────────

    /// <summary>When true, the <c>urn:ietf:params:oauth:grant-type:jwt-bearer</c> grant is active.</summary>
    public bool JwtBearerGrantEnabled { get; set; } = false;

    /// <summary>
    /// Decides whether a client may obtain a token for the subject named in its JWT
    /// assertion. When <c>null</c>, every jwt-bearer grant is denied: a client asserting an
    /// arbitrary <c>sub</c> would otherwise be able to impersonate any user.
    /// </summary>
    public Func<JwtBearerContext, CancellationToken, Task<bool>>? AuthorizeJwtBearerSubject { get; set; }

    // ── Phase 5 — DPoP (RFC 9449) ────────────────────────────────────────────

    /// <summary>
    /// When true, the token endpoint accepts a <c>DPoP</c> header and issues
    /// DPoP-bound access tokens.  DPoP proofs are also validated on the UserInfo endpoint.
    /// </summary>
    public bool DPoPEnabled { get; set; } = false;

    /// <summary>Allowed IAT drift for DPoP proofs in seconds (default 300 = 5 min).</summary>
    public int DPoPProofLifetimeSeconds { get; set; } = 300;

    /// <summary>
    /// Require DPoP proofs to carry a server-provided nonce (RFC 9449 §8). Clients learn the
    /// nonce from a <c>use_dpop_nonce</c> error and the <c>DPoP-Nonce</c> response header.
    /// </summary>
    public bool DPoPRequireNonce { get; set; } = false;

    /// <summary>How long a DPoP server nonce is accepted, in seconds (default 300).</summary>
    public int DPoPNonceLifetimeSeconds { get; set; } = 300;

    /// <summary>
    /// Secret for DPoP nonces. Set the same value on every instance so nonces issued by one are
    /// accepted by all; when null a per-process secret is used.
    /// </summary>
    public string? DPoPNonceSecret { get; set; }

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

    /// <summary>
    /// Addresses (IP or CIDR, e.g. <c>10.0.0.0/8</c>) of the reverse proxies allowed to supply
    /// <see cref="MtlsClientCertificateHeader"/>. The header is ignored from any other peer, so
    /// clients cannot forge a certificate by sending the header themselves.
    /// </summary>
    public IList<string> MtlsTrustedProxies { get; set; } = [];

    /// <summary>
    /// Trust anchors for <c>tls_client_auth</c> certificates. When empty, the operating
    /// system's trusted root store is used.
    /// </summary>
    public IList<System.Security.Cryptography.X509Certificates.X509Certificate2> MtlsCertificateAuthorities { get; set; } = [];

    /// <summary>Revocation checking for <c>tls_client_auth</c> chains (default: no check).</summary>
    public System.Security.Cryptography.X509Certificates.X509RevocationMode MtlsRevocationMode { get; set; }
        = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;

    /// <summary>
    /// Maximum remaining lifetime (<c>exp</c> − now) accepted for <c>private_key_jwt</c> and
    /// <c>client_secret_jwt</c> assertions. Default 300 s.
    /// </summary>
    public int ClientAssertionMaxLifetimeSeconds { get; set; } = 300;

    /// <summary>
    /// Attesters trusted for attestation-based client authentication (<c>attest_jwt_client_auth</c>,
    /// draft-ietf-oauth-attestation-based-client-auth): attester <c>iss</c> → its JWKS (JSON).
    /// Empty disables the method. The PoP's <c>iat</c> must be within
    /// <see cref="ClientAssertionMaxLifetimeSeconds"/>.
    /// </summary>
    public IDictionary<string, string> ClientAttestationTrustedAttesters { get; set; } = new Dictionary<string, string>();

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

    /// <summary>
    /// Wrong or expired user codes a signed-in user may enter per
    /// <see cref="DeviceUserCodeFailureWindowSeconds"/> before further attempts are refused
    /// (RFC 8628 §5.1). Default 5.
    /// </summary>
    public int DeviceUserCodeMaxFailedAttempts { get; set; } = 5;

    /// <summary>Window for <see cref="DeviceUserCodeMaxFailedAttempts"/> in seconds (default 300).</summary>
    public int DeviceUserCodeFailureWindowSeconds { get; set; } = 300;

    // ── Abuse protection ──────────────────────────────────────────────────────

    /// <summary>
    /// Per-IP request budget per minute for endpoints that require no credentials or accept
    /// untrusted input before authenticating (c_nonce, registration, device authorization).
    /// 0 disables the limit. Default 60.
    /// </summary>
    public int UnauthenticatedRequestsPerMinute { get; set; } = 60;

    // ── Phase 6 — CIBA (OpenID CIBA Core 1.0) ────────────────────────────────

    /// <summary>When true, the backchannel authentication endpoint is active (poll mode).</summary>
    public bool CibaEnabled { get; set; } = false;

    public string BackchannelAuthenticationEndpoint { get; set; } = "/connect/ciba";

    /// <summary>Lifetime in seconds of <c>auth_req_id</c> tokens (default 120 s).</summary>
    public int CibaAuthReqIdLifetimeSeconds { get; set; } = 120;

    /// <summary>Minimum polling interval in seconds for the CIBA poll mode (default 5 s).</summary>
    public int CibaPollingIntervalSeconds { get; set; } = 5;

    /// <summary>Upper bound in seconds for a client's <c>requested_expiry</c> (default 600).</summary>
    public int CibaMaxRequestedExpirySeconds { get; set; } = 600;

    /// <summary>Maximum length of a CIBA <c>binding_message</c> (default 64 characters).</summary>
    public int CibaMaxBindingMessageLength { get; set; } = 64;

    /// <summary>
    /// Hook called (in the background) after a CIBA request is accepted. The implementation
    /// starts out-of-band authentication and later calls <see cref="Ciba.ICibaService.CompleteAsync"/>
    /// to approve or deny the request.
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

    /// <summary>
    /// <c>federation_entity</c> metadata published in the entity configuration, e.g.
    /// <c>organization_name</c>, <c>homepage_uri</c>, <c>contacts</c>, <c>logo_uri</c>, <c>policy_uri</c>.
    /// </summary>
    public IDictionary<string, object> FederationEntityMetadata { get; set; } = new Dictionary<string, object>();

    /// <summary>
    /// Trust anchors: entity identifier → JWKS (JSON). A relying party is trusted only when a
    /// valid trust chain from it ends at one of these anchors, verified with these keys.
    /// </summary>
    public IDictionary<string, string> FederationTrustAnchors { get; set; } = new Dictionary<string, string>();

    /// <summary>Accept unregistered relying parties whose entity id resolves to a trust chain (§12.1).</summary>
    public bool FederationAutomaticRegistrationEnabled { get; set; } = true;

    /// <summary>Expose the explicit registration endpoint (§12.2).</summary>
    public bool FederationExplicitRegistrationEnabled { get; set; } = true;

    public string FederationRegistrationEndpoint { get; set; } = "/connect/federation_registration";

    /// <summary>Maximum number of statements in a trust chain (default 5).</summary>
    public int FederationMaxChainLength { get; set; } = 5;

    /// <summary>Maximum size of a fetched entity statement in bytes (default 65536).</summary>
    public int FederationMaxStatementBytes { get; set; } = 65536;

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
    /// Hook invoked to issue credentials after the access token and key proofs have been
    /// verified. Return one credential (JWT-VC, SD-JWT, ...) per key in
    /// <see cref="Vci.CredentialIssuanceRequest.HolderPublicJwks"/>, each bound to that key, or
    /// <see cref="Vci.CredentialIssuanceResult.Deferred"/> when issuance is not immediate. A plain
    /// string converts implicitly to a single issued credential.
    /// </summary>
    public Func<Vci.CredentialIssuanceRequest, CancellationToken, Task<Vci.CredentialIssuanceResult>>? IssueCredential { get; set; }

    /// <summary>
    /// Hook polled by the deferred credential endpoint (OID4VCI 1.0 §9) for issuances that
    /// <see cref="IssueCredential"/> deferred. Required when that hook ever defers.
    /// </summary>
    public Func<Vci.DeferredCredentialRequest, CancellationToken, Task<Vci.CredentialIssuanceResult>>? RetrieveDeferredCredential { get; set; }

    /// <summary>Hook receiving wallet notifications (OID4VCI 1.0 §11): accepted, failed, deleted.</summary>
    public Func<Vci.CredentialNotification, CancellationToken, Task>? OnCredentialNotification { get; set; }

    /// <summary>Credential offer endpoint path; offers are served at <c>{path}/{id}</c> (OID4VCI 1.0 §4.1.3).</summary>
    public string VciCredentialOfferEndpoint { get; set; } = "/connect/credential_offer";

    /// <summary>Deferred credential endpoint path (OID4VCI 1.0 §9).</summary>
    public string VciDeferredCredentialEndpoint { get; set; } = "/connect/deferred_credential";

    /// <summary>Notification endpoint path (OID4VCI 1.0 §11).</summary>
    public string VciNotificationEndpoint { get; set; } = "/connect/notification";

    /// <summary>Lifetime of credential offers and their pre-authorized codes (default 300 s).</summary>
    public int VciPreAuthorizedCodeLifetimeSeconds { get; set; } = 300;

    /// <summary>Wrong <c>tx_code</c> attempts after which a pre-authorized code is revoked.</summary>
    public int VciTxCodeMaxAttempts { get; set; } = 5;

    /// <summary>
    /// When true, the pre-authorized code grant is accepted without client authentication or a
    /// <c>client_id</c> (OID4VCI 1.0 §6.1, <c>pre-authorized_grant_anonymous_access_supported</c>).
    /// </summary>
    public bool VciPreAuthorizedAnonymousAccess { get; set; } = false;

    /// <summary>Maximum number of key proofs (and credentials) per request; above 1 enables batch issuance.</summary>
    public int VciBatchSize { get; set; } = 1;

    /// <summary>How long a deferred transaction can be redeemed (default 1 day).</summary>
    public int VciDeferredTransactionLifetimeSeconds { get; set; } = 86400;

    /// <summary>How long a <c>notification_id</c> can be used (default 1 day).</summary>
    public int VciNotificationLifetimeSeconds { get; set; } = 86400;

    // ── Phase 8 — CORS ─────────────────────────────────────────────────────────

    /// <summary>When true, CORS headers are applied to OIDC provider endpoints.</summary>
    public bool CorsEnabled { get; set; } = false;

    /// <summary>
    /// Additional allowed CORS origins. The origins of static clients' redirect URIs are always
    /// allowed; a wildcard is never used. Dynamically registered clients must be listed here.
    /// </summary>
    public IList<string> CorsAllowedOrigins { get; set; } = [];

    // ── Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document) ──

    /// <summary>
    /// Accept https URLs as <c>client_id</c>s: the provider fetches the client's metadata document
    /// from the URL and treats it as the registration (public or <c>private_key_jwt</c> clients).
    /// </summary>
    public bool ClientIdMetadataDocumentEnabled { get; set; } = false;

    /// <summary>Hosts whose metadata documents are accepted; empty means any public host.</summary>
    public IList<string> ClientIdMetadataDocumentAllowedHosts { get; set; } = [];

    /// <summary>Maximum size of a metadata document (or its JWKS) in bytes (default 5120).</summary>
    public int ClientIdMetadataDocumentMaxBytes { get; set; } = 5120;

    /// <summary>Cache lifetime when the document has no <c>Cache-Control: max-age</c> (default 3600 s).</summary>
    public int ClientIdMetadataDocumentCacheSeconds { get; set; } = 3600;
}
