# Changelog

All notable changes to NetOidc are documented here. The project is pre-1.0: breaking
changes are allowed between minor versions and are listed explicitly.

## [Unreleased]

Security remediation, specification conformance, operability and completed features, Phases 1–5
(see [docs/REMEDIATION_PLAN.md](docs/REMEDIATION_PLAN.md)).

### Features — Phase 5

- OpenID Federation 1.1: separate federation keys (`AddFederationKey`), trust chain resolution to
  configured trust anchors (`FederationTrustAnchors`) with metadata policies, automatic
  registration, and explicit registration (`/connect/federation_registration`). The entity
  configuration now carries the same metadata as discovery.
- OID4VCI 1.0 final: credential offers (`CredentialOfferService`), the pre-authorized code grant with
  transaction codes and optional anonymous access, `openid_credential` authorization details,
  `credentials` array responses with batch issuance, deferred issuance and notifications.
- Client ID Metadata Documents: URL `client_id`s are fetched, validated and cached (`ClientIdMetadataDocumentEnabled`).
- Signed and encrypted UserInfo responses (`userinfo_signed_response_alg`, `userinfo_encrypted_response_*`).
- Attestation-based client authentication (`attest_jwt_client_auth`, `ClientAttestationTrustedAttesters`).
- Dynamic registration of `private_key_jwt`/`client_secret_jwt` clients with `jwks`/`jwks_uri`,
  signing and encryption algorithms, and RP Metadata Choices.
- `RenderErrorPage` hook for errors that cannot be returned to the client.
- Discovery advertises exactly what is enabled, per FAPI profile and configured keys.
- Token responses include the granted `authorization_details` (RFC 9396 §7).
- Fixed: encrypted request objects could never be decrypted.
- Fixed: untrusted JSON with non-string values could cause server errors in new parsers (guarded throughout).

### Breaking changes — Phase 5

- `ProviderOptions.IssueCredential` returns `Task<CredentialIssuanceResult>` (return one credential
  per holder key; a string converts implicitly). The credential response is
  `{"credentials":[{"credential":…}]}` instead of `{"credential":…}`.
- A credential configuration without `Scope` is only issued when the token's authorization details
  include it.
- The credential endpoint returns `invalid_credential_request`, `unknown_credential_configuration`
  and `unknown_credential_identifier` (OID4VCI 1.0) instead of `invalid_request`.
- `RSA-OAEP-256` is no longer accepted for encryption keys or client encryption (it never worked
  with Microsoft.IdentityModel); the default is `RSA-OAEP`. AES-GCM is no longer advertised for
  responses encrypted to clients.
- The default `id_token_encrypted_response_enc` is `A128CBC-HS256` (was `A256CBC-HS512`).
- Federation automatic registration requires `JarEnabled`; the federation registration endpoint
  moved from `RegistrationEndpoint` to `FederationRegistrationEndpoint`.
- `FederationService` takes a `DiscoveryService`; federation statements are signed with the
  federation key rather than the OP signing key.
- `ClientAuthenticator` takes a `ClientAttestationValidator`.
- New startup validations: federation trust anchors, attesters, VCI and CIMD limits, encrypted-response
  client settings.

### Operability — Phase 4

- Configurable, rotatable keys (`AddSigningKey`, `AddSigningCertificate`, `AddEncryptionKey`,
  `UseKeyStore<T>()` for vault/HSM/KMS). All published keys verify; future keys are pre-published;
  expired keys retire. RS/PS/ES algorithms, per-client ID token and JARM algorithms.
- A Production host refuses to start with generated keys; key algorithms and types are validated.
- Structured logging across all endpoints (no tokens or secrets) and new failure/lifecycle events.
- DPoP server nonces (RFC 9449 §8), shareable across instances; VCI nonces via `IAdapter<CredentialNonce>`.
- Startup validation of the whole `ProviderOptions` graph (issuer, lifetimes, paths, feature
  prerequisites, static clients).
- Opaque access tokens (`AccessTokenFormat`), stored by hash.
- Tracing, metrics and a key health check (`NetOidc.Provider`, `AddNetOidcKeys()`).

### Conformance — Phase 3

- Public clients (`token_endpoint_auth_method=none`) with mandatory PKCE.
- The authorization endpoint accepts POST, and supports `prompt` (`none`, `login`, `consent`,
  `select_account`), `max_age`, `id_token_hint`, `login_hint`, `ui_locales`, `acr_values` and the
  `claims` parameter. Requests suspended for login or consent resume where they left off, including
  pushed requests.
- Consent is stored per client and user (`ConsentService`); clients require consent by default.
- ID tokens carry `at_hash`/`c_hash`, the real `auth_time`, and are encrypted at the token endpoint
  when the client registered encryption. Claims are released only per scope or `claims` request.
- Pairwise subjects are consistent everywhere (tokens, UserInfo, introspection, logout tokens), while
  the claims source always receives the local subject.
- JAR uses only the request object's parameters; `request_uri` by reference is rejected explicitly.
- PKCE accepts only S256 unless `AllowPlainPkce`; malformed challenges/verifiers are rejected.
- Authorization codes, refresh tokens and access tokens share a grant; replaying a code revokes them.
- `grant_types` and `response_types` are enforced per client; refresh supports scope downscoping,
  ID tokens on refresh and optional non-rotation.
- Resource indicators are validated against an allowlist and become the access-token audience.
- FAPI profiles are enforced at runtime (PAR/JAR/JARM requirements, sender-constrained tokens).
- CIBA supports ping and push delivery, signed requests, `requested_expiry`, `binding_message` and
  `user_code`; the host resolves requests through `ICibaService`.
- Device flow `slow_down` raises the interval; scopes are validated.
- Logout asks for confirmation without a valid `id_token_hint`, finds the session from its cookie,
  expires sessions, supports front-channel logout, and types logout tokens `logout+jwt`.
- Fixed: back-channel logout tokens could never be serialized (no logout notification was ever sent).
- Fixed: a pushed request was consumed before the login redirect, so it could not be resumed.

### Security — Phase 2 (hardening)

- Client assertions must have `iss` = `sub` = client_id, a single-use `jti`, a short lifetime and an
  allowed algorithm; `client_secret_jwt` uses the raw secret, which must be long enough for the hash.
  Requests presenting more than one client authentication method are rejected.
- The mTLS certificate header is honoured only from configured proxies; `tls_client_auth` validates
  the certificate chain; subject DNs are compared per RFC 4514; every SAN URI is checked.
- `redirect_uri` must be repeated at the token endpoint when it was sent in the authorization request.
- UserInfo rejects revoked tokens, enforces DPoP and certificate binding (no Bearer downgrade),
  requires the `openid` scope and returns RFC 6750 challenges.
- Revoking a refresh token (or detected reuse) also revokes access tokens issued with it.
- Device approval requires an antiforgery token and limits wrong user-code attempts; the sample
  login form uses antiforgery.
- In-memory stores sweep expired entries; per-IP request budgets protect the nonce, registration
  and device authorization endpoints; DPoP `jti` tracking uses `IReplayCache`.
- CORS applies only to discovery, JWKS, token, userinfo and revocation, never with a wildcard origin.
- Library and hook exception details are logged instead of returned to clients.

### Security — Phase 1

- RP-initiated logout no longer redirects to unregistered `post_logout_redirect_uri` values (open redirect).
- Token exchange enforces the client's grant type, bounds scopes by the subject token and client,
  rejects revoked/expired subject tokens, and by default only lets a client exchange its own tokens.
- The jwt-bearer grant requires an explicit subject policy, a `jti`, and rejects replayed assertions.
- One-time artifacts (authorization codes, refresh tokens, PAR request URIs, device codes, CIBA
  requests) are redeemed atomically.
- OID4VCI key proofs are cryptographically verified, require a single-use `c_nonce`, and the access
  token must carry an End-User subject and the credential configuration's scope.
- Dynamic client registration validates redirect/logout/informational URIs, restricts grant types,
  defaults to PKCE, and blocks SSRF through `backchannel_logout_uri`.
- Request objects pushed to PAR are validated; client authentication parameters are never persisted.
- Refresh tokens rotate within families with reuse detection; revoking one revokes its family;
  tokens bound to a DPoP key or certificate require the same key.
- Introspection only discloses tokens issued to, or addressed to, the caller unless authorised by policy.
- The client metadata endpoint that disclosed every client's registration was removed.
- Pairwise subjects require a secret salt and are computed per sector identifier.

### Breaking changes

- `IAdapter<T>.ConsumeAsync` must now be atomic; custom adapters must guarantee a single winner.
- `ProviderOptions.IssueCredential` signature is now `Func<CredentialIssuanceRequest, CancellationToken, Task<string>>`.
- `ProviderOptions.ClientIdMetadataDocumentEnabled` and `/.well-known/client_id_metadata/{clientId}` were removed.
- Token exchange requires `urn:ietf:params:oauth:grant-type:token-exchange` in the client's
  `AllowedGrantTypes`; cross-client exchange requires `AuthorizeTokenExchange`.
- The jwt-bearer grant requires the grant type on the client, `AuthorizeJwtBearerSubject`, and a `jti`.
- The credential endpoint rejects tokens without a `sub` and, for configurations with a binding
  method (the default), requests without a key proof.
- DCR rejects grant types outside `DcrAllowedGrantTypes` (default `authorization_code`, `refresh_token`)
  and dynamic clients now default to `RequirePkce = true`.
- `SubjectIdentifierService.Compute` takes a `Client`; pairwise subject values change; startup fails
  without a `PairwiseSalt` of at least 32 bytes.
- Invalid options now fail at startup (`ValidateOnStart`).
- `TokenEndpointHandler`, `IntrospectionEndpointHandler`, `RevocationEndpointHandler`,
  `ParEndpointHandler`, `VciEndpointHandler` and `BackChannelLogoutService` constructors changed
  (relevant only when constructed manually).
- Phase 2: `ClientAuthenticator` is an injected service instead of a static class.
- Phase 2: `RefreshTokenService.IssueAsync`/`IssueSuccessorAsync` return `IssuedRefreshToken`.
- Phase 2: the mTLS certificate header is ignored unless the peer is in `MtlsTrustedProxies`, and
  `tls_client_auth` certificates must chain to `MtlsCertificateAuthorities` (or the OS trust store).
- Phase 2: client assertions without a `jti`, with `sub` ≠ `iss`, or living longer than
  `ClientAssertionMaxLifetimeSeconds` are rejected; `client_secret_jwt` no longer hashes short secrets.
- Phase 2: UserInfo requires the `openid` scope and the DPoP scheme for DPoP-bound tokens.
- Phase 2: device approval `POST` requires the antiforgery token returned by the `GET` prompt.
- Phase 2: CORS no longer allows any origin when `CorsAllowedOrigins` is empty, and no longer applies
  to authorize, introspection, PAR, device, CIBA, registration, federation or VCI endpoints.
- Phase 2: `ValidateDynamicClient` exception messages are only returned for `ClientMetadataValidationException`.
- Phase 2: `DPopProofValidator`, `UserInfoEndpointHandler`, `DeviceVerificationEndpointHandler`,
  `DeviceAuthorizationEndpointHandler`, `DynamicRegistrationEndpointHandler`, `RequestObjectValidator`
  and `VciEndpointHandler` constructors changed.

- Phase 3: `ProviderOptions.FindUserClaims` is now
  `Func<UserClaimsRequest, CancellationToken, Task<IReadOnlyDictionary<string, object>>>` and its
  output is filtered to scope-released or requested claims (it receives the local subject).
- Phase 3: `IInteractionService` is replaced by `EvaluateAsync(InteractionRequest)` returning an
  `InteractionOutcome`; `DefaultInteractionService` no longer auto-consents.
- Phase 3: `Client.RequireConsent` defaults to true — set it to false for first-party clients or
  provide a consent page at `ConsentPath`.
- Phase 3: the `"hybrid"` grant type is removed; clients declare `ResponseTypes` (default `code`) and
  hybrid clients list `authorization_code` and `implicit`.
- Phase 3: refresh tokens are only issued to clients whose `AllowedGrantTypes` include `refresh_token`,
  and the refresh grant requires it.
- Phase 3: PKCE `plain` (and a missing `code_challenge_method`) is rejected unless `AllowPlainPkce`.
- Phase 3: resource indicators require `AllowedResources`; `AccessToken.Resource` became `Resources`.
- Phase 3: JAR requests ignore parameters outside the request object; `request_uri` must come from PAR.
- Phase 3: FAPI 1.0 no longer accepts `client_secret_jwt` or public clients; FAPI profiles require
  PAR/JAR as described in the remediation plan, and FAPI 2.0 refuses unbound tokens.
- Phase 3: logout without a valid `id_token_hint` redirects to `LogoutConfirmationPath`.
- Phase 3: `RefreshTokenService` API (`IssueAsync(Client, RefreshTokenContent, …)`, `RedeemAsync`),
  `SubjectIdentifierService`, CIBA and device models changed; most endpoint handler constructors changed.

- Phase 4: `SigningKeyProvider` and `EncryptionKeyProvider` are replaced by `IKeyStore` and `KeyRing`;
  `TokenFactory`, `RequestObjectValidator`, `DiscoveryService` and `FederationService` take `KeyRing`.
- Phase 4: Production hosts must configure keys; invalid options (e.g. an http issuer outside
  Development, `CibaEnabled` without its hook, `VciEnabled` without `IssueCredential`, clients
  without the credentials their auth method needs) fail at startup.
- Phase 4: `VciService` is async and stores nonces through `IAdapter<CredentialNonce>`.
- Phase 4: `AccessTokenService.ValidatedAccessToken.Principal` is null for opaque tokens; the
  introspection response is built from the stored record.
- Phase 4: `ClientAuthenticator`, `TokenIssuanceService`, `CibaService` and most endpoint handlers
  take additional constructor dependencies (logger, event sink, nonce service).

### Added

- Phase 4: `IKeyStore`, `ConfiguredKeyStore`, `KeyRing`, `ProviderKey`, `DPoPNonceService`,
  `NetOidcTelemetry`, `KeyHealthCheck`/`AddNetOidcKeys()`, `CredentialNonce`; events
  `ClientAuthenticationFailed`, `TokenRequestFailed`, `AuthorizationFailed`, `LoggedOut`,
  `AuthorizationDecision`, `ClientRegistrationChanged`.
- Phase 4 `ProviderOptions`: `Keys`, `DefaultSigningAlgorithm`, `AccessTokenFormat`,
  `DPoPRequireNonce`, `DPoPNonceLifetimeSeconds`, `DPoPNonceSecret`; `Client.IdTokenSignedResponseAlg`,
  `Client.AccessTokenFormat`; `AccessToken.IssuedAt`.
- Phase 3: `TokenIssuanceService`, `GrantService`, `ConsentService`, `UserClaimsService`,
  `ICibaService`/`CibaService`, `ResourceIndicators`; models `Consent`, `PendingInteraction`.
- Phase 3 `ProviderOptions`: `ConsentPath`, `InteractionLifetimeSeconds`, `RotateRefreshTokens`,
  `AllowPlainPkce`, `AllowedResources`, `LogoutConfirmationPath`, `SessionLifetimeSeconds`,
  `FrontChannelLogoutEnabled`, `CibaMaxRequestedExpirySeconds`, `CibaMaxBindingMessageLength`.
- Phase 3 `Client`: `ResponseTypes`, `RequireConsent`, `AllowedResources`, `FrontChannelLogoutUri`,
  `FrontChannelLogoutSessionRequired`, `BackchannelUserCodeParameter`; `Scope.Claims`.
- Phase 3 discovery: `prompt_values_supported`, `claims_supported`, `request_uri_parameter_supported`,
  front-channel logout metadata, `none` auth method, CIBA `ping`/`push`.

- Phase 2: `AccessTokenService`, `RequestThrottle`, `ClientMetadataValidationException`,
  `AuthorizationCode.RedirectUriInRequest`.
- Phase 2 `ProviderOptions`: `ClientAssertionMaxLifetimeSeconds`, `MtlsTrustedProxies`,
  `MtlsCertificateAuthorities`, `MtlsRevocationMode`, `DeviceUserCodeMaxFailedAttempts`,
  `DeviceUserCodeFailureWindowSeconds`, `UnauthenticatedRequestsPerMinute`.

- `IReplayCache` (with `InMemoryReplayCache`), `RefreshTokenService`.
- `ProviderOptions`: `AuthorizeTokenExchange`, `AuthorizeJwtBearerSubject`, `AuthorizeIntrospection`,
  `DcrAllowedGrantTypes`, `DcrAllowPrivateNetworkUris`.
- `Client.SectorIdentifierUri`; `RefreshToken.GrantId`, `ConsumedAt`, `CnfJwkThumbprint`, `CnfX5tS256`.
- Introspection responses include `cnf`, `aud`, the real `iat`, and `token_type: DPoP` for bound tokens.
