# Changelog

All notable changes to NetOidc are documented here. The project is pre-1.0: breaking
changes are allowed between minor versions and are listed explicitly.

## [Unreleased]

Security remediation, Phases 1–2 (see [docs/REMEDIATION_PLAN.md](docs/REMEDIATION_PLAN.md)).

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

### Added

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
