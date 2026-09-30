# NetOidc — Remediation Plan

Findings from a full cross-check of `src/` against the relevant specifications and
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) (review date: 2026-09-28, commit `ed134dd`).
All 191 existing tests pass; none of them cover the defects listed here.

## Decisions

| Decision | Outcome |
|----------|---------|
| Target | **Production readiness + OpenID conformance certification.** Features advertised in discovery must be fully implemented, not hidden. |
| Breaking changes | **Allowed** (pre-1.0), including `NetOidc.Provider.Abstractions`. Record each in the changelog. |
| Working method | One branch per phase. Every fix lands with a regression test that fails before the fix. |

## How to use this document

- Each item has an ID (`P1.3`), the affected code, the required change, and an acceptance test.
- Tick the checkbox when the fix and its test are merged.
- Items marked **BREAKING** change a public contract.
- The README status table must be updated to reflect this plan: phases 0–9 are not "Done"
  until the related items below are closed.

---

## Phase 1 — Exploitable security defects

Goal: close every issue that an external attacker or a malicious registered client can exploit.

- [x] **P1.1 Open redirect on RP-initiated logout**
  - Code: [LogoutEndpointHandler.cs:478-486](../src/NetOidc.Provider/Logout/LogoutEndpointHandler.cs#L478-L486)
  - Problem: `post_logout_redirect_uri` is only validated when a client is identified *and* has
    registered URIs. Without `id_token_hint`/`client_id`, or with an empty list, any URL is accepted.
  - Fix: honour `post_logout_redirect_uri` only when the client is identified and the URI is an
    exact match in `PostLogoutRedirectUris`; otherwise ignore it and show the logged-out page.
    Reject a `client_id` that differs from the `id_token_hint` audience. Append `state` with
    `QueryHelpers.AddQueryString` (fixes a `?` vs `&` bug as well).
  - Test: logout with an arbitrary URI and no hint → no redirect; with an unregistered URI → 400.

- [x] **P1.2 Token Exchange privilege escalation** (RFC 8693)
  - Code: [TokenEndpointHandler.cs:349-438](../src/NetOidc.Provider/Token/TokenEndpointHandler.cs#L349-L438)
  - Problems: no `AllowedGrantTypes` check; requested `scope` is not bounded by the subject
    token's scopes or `client.AllowedScopes`; any client can exchange another client's refresh
    token; `id_token` subject tokens are accepted when expired (`ValidateIdTokenHintAsync`
    disables lifetime checks); the access-token store lookup uses the raw JWT as key (store is
    keyed by `jti`) so revocation is never observed.
  - Fix: require the grant type on the client; scopes ⊆ subject-token scopes ∩ client scopes;
    add an `ExchangeTokenPolicy` hook in `ProviderOptions` (who may exchange what, audience,
    `actor_token` / `may_act`); validate id_tokens with lifetime and audience; look up access
    tokens by validated `jti`; support `audience`/`resource` and `actor_token`.
  - Test: escalation to an unheld scope → `invalid_scope`; revoked/expired subject token →
    `invalid_grant`; foreign refresh token → `invalid_grant`.

- [x] **P1.3 JWT-bearer grant impersonation** (RFC 7523)
  - Code: [TokenEndpointHandler.cs:442-511](../src/NetOidc.Provider/Token/TokenEndpointHandler.cs#L442-L511)
  - Problems: any client with a JWKS can assert any `sub`; no grant-type check; no `jti`
    replay protection; scopes not bounded by `client.AllowedScopes`.
  - Fix: require the grant type; add a `ValidateJwtBearerSubject` policy hook (default: deny
    unless configured); enforce `jti` uniqueness via the replay cache (P4.3); bound scopes.
  - Test: replayed assertion → `invalid_grant`; assertion for arbitrary sub without policy → denied.

- [x] **P1.4 Non-atomic one-time consumption** — **BREAKING** (adapter contract)
  - Code: [InMemoryAdapter.cs:37-43](../src/NetOidc.Provider/Adapters/InMemoryAdapter.cs#L37-L43),
    [IAdapter.cs](../src/NetOidc.Provider.Abstractions/Adapters/IAdapter.cs)
  - Problem: `ConsumeAsync` does Find then TryRemove, so concurrent requests can redeem the
    same authorization code, refresh token or PAR `request_uri` twice.
  - Fix: implement with `ConcurrentDictionary.TryRemove(key, out value)`; document in
    `IAdapter<T>` that `ConsumeAsync` MUST be atomic; use `ConsumeAsync` for device-code and
    CIBA approvals too. Per RFC 6749 §4.1.2, a replayed code should revoke tokens issued from
    it (requires grant tracking, see P3.9).
  - Test: 50 parallel redemptions of one code → exactly one success.

- [x] **P1.5 OID4VCI proof signature never verified**
  - Code: [VciEndpointHandler.cs:453-491](../src/NetOidc.Provider/Vci/VciEndpointHandler.cs#L453-L491)
  - Problems: the proof JWT is only parsed, never cryptographically verified; nonce is optional;
    the access token's scope/`authorization_details` is not checked against the requested
    credential configuration; the issued credential is not bound to the holder key.
  - Fix: verify the signature with the header `jwk`/`kid`/`x5c`; require and consume `c_nonce`;
    check `iat` freshness; authorise the configuration from the token; pass the holder's public
    key to `IssueCredential` (**BREAKING** hook signature).
  - Test: forged/unsigned proof → `invalid_proof`; missing nonce → `invalid_nonce`.

- [x] **P1.6 Dynamic Client Registration accepts unsafe metadata**
  - Code: [DynamicRegistrationEndpointHandler.cs:194-257](../src/NetOidc.Provider/Dcr/DynamicRegistrationEndpointHandler.cs#L194-L257)
  - Problems: `redirect_uris` not validated (`javascript:`, fragments, `http` to non-loopback
    all accepted); arbitrary `grant_types` accepted (e.g. `client_credentials`, token exchange);
    `RequirePkce` defaults to `false`; `backchannel_logout_uri` enables SSRF against internal hosts.
  - Fix: validate URIs per RFC 7591 §2 / OIDC Registration §2 (absolute, no fragment, `https`
    except loopback/private-use schemes for native apps); restrict grant types to an
    operator-configured allowlist and require matching `response_types`; default
    `RequirePkce = true`; validate `backchannel_logout_uri` (https, no private/loopback IPs unless
    allowed) and send logout requests through a hardened named `HttpClient` (timeouts, no redirects).
    Also support `jwks`/`jwks_uri`, `private_key_jwt`, `id_token_signed_response_alg` and the
    other metadata the provider already implements.
  - Test: registration with `javascript:` URI → `invalid_redirect_uri`; disallowed grant → `invalid_client_metadata`.

- [x] **P1.7 PAR bypasses JAR validation**
  - Code: [ParEndpointHandler.cs](../src/NetOidc.Provider/Par/ParEndpointHandler.cs),
    [AuthorizationEndpointHandler.cs:362-382](../src/NetOidc.Provider/Authorization/AuthorizationEndpointHandler.cs#L362-L382)
  - Problem: a `request` JWT pushed to PAR is stored verbatim and never verified, so FAPI 2
    Message Signing is not enforced. `client_assertion` is persisted with the parameters.
  - Fix: run `RequestObjectValidator` at the PAR endpoint and store the verified claims; run
    the full authorization-request validation (scope, redirect_uri, PKCE, response_type) at PAR
    time (RFC 9126 §2.1); strip all client-auth parameters before persisting.
  - Test: PAR with a tampered request object → 400; a stored PAR contains no `client_assertion`.

- [x] **P1.8 Refresh tokens are not sender-constrained**
  - Code: [TokenEndpointHandler.cs:232-293](../src/NetOidc.Provider/Token/TokenEndpointHandler.cs#L232-L293),
    [RefreshToken.cs](../src/NetOidc.Provider.Abstractions/Models/RefreshToken.cs)
  - Fix: store `CnfJwkThumbprint`/`CnfX5tS256` on refresh tokens (**BREAKING** model); for
    public clients require the same DPoP key on refresh (RFC 9449 §5); add refresh-token family
    IDs and revoke the whole family on reuse (OAuth 2.0 Security BCP §4.14).
  - Test: refresh with a different DPoP key → `invalid_grant`; reuse of a rotated token revokes the family.

- [x] **P1.9 Introspection exposes any token to any client**
  - Code: [IntrospectionEndpointHandler.cs:82-112](../src/NetOidc.Provider/Token/IntrospectionEndpointHandler.cs#L82-L112)
  - Fix: introduce protected-resource registrations (or an `CanIntrospect(caller, token)` hook);
    by default a client may introspect only tokens issued to it or whose `aud` includes it.
    Return correct `token_type` (`DPoP` when bound), `cnf`, `aud`, real `iat`.
  - Test: client B introspecting client A's token → `{active:false}`.

- [x] **P1.10 Client metadata endpoint leaks all clients**
  - Code: [ClientIdMetadataEndpointHandler.cs](../src/NetOidc.Provider/Discovery/ClientIdMetadataEndpointHandler.cs)
  - Problem: unauthenticated callers can read `redirect_uris` and `jwks` of every client; the
    feature also does not implement the Client ID Metadata Document draft.
  - Fix: remove this endpoint. Implement the draft properly (Phase 5, P5.5): when `client_id`
    is an https URL, fetch and cache the metadata document with SSRF protections.
  - Test: `GET /.well-known/client_id_metadata/{id}` → 404.

- [x] **P1.11 Predictable pairwise subjects**
  - Code: [SubjectIdentifierService.cs:31](../src/NetOidc.Provider/Claims/SubjectIdentifierService.cs#L31)
  - Fix: require `PairwiseSalt` (min 32 bytes) when `SubjectType = "pairwise"` via options
    validation; derive per `sector_identifier_uri` host, not `client_id` (OIDC Core §8.1).
  - Test: startup fails for pairwise without salt.

### Phase 1 — implementation notes (branch `fix/p1-security`)

All eleven items are implemented with regression tests (279 tests pass). The new tests that
compile against the pre-fix code were run there and fail as expected. Where the
implementation differs from the text above, or leaves work for a later item:

| Item | Note |
|------|------|
| P1.1 | An unregistered or unattributable `post_logout_redirect_uri` returns 400 rather than a logged-out page (no UI exists yet). An unverifiable `id_token_hint` is treated as absent, so logout still succeeds after key changes. |
| P1.2 | New `ProviderOptions.AuthorizeTokenExchange`. `actor_token` is rejected with `invalid_request` until delegation is implemented. `audience`/`resource` reach the policy but do not yet shape the token `aud` (P3.12). |
| P1.3 | New `ProviderOptions.AuthorizeJwtBearerSubject` (default deny) and `IReplayCache` (in-memory default; distributed store is P4.3). |
| P1.4 | Device-code and CIBA approvals now also redeem via `ConsumeAsync`. Code-replay token revocation still needs grant linkage (P3.9). |
| P1.5 | `IssueCredential` now takes a `CredentialIssuanceRequest` with the proven holder JWKs. Only the `jwk` binding method is supported (`kid`/`x5c` are refused). DPoP-bound access tokens are not yet accepted at the credential endpoint. |
| P1.6 | New `DcrAllowedGrantTypes` (default `authorization_code`, `refresh_token`) and `DcrAllowPrivateNetworkUris`. Back-channel logout to dynamic clients uses an HTTP client that refuses non-public addresses at connect time. DCR support for `jwks`/`private_key_jwt` metadata remains open. |
| P1.7 | Full authorization-request validation at PAR covers response_type, redirect_uri and scope; PKCE/response_type semantics are revalidated at the authorization endpoint. |
| P1.8 | Families are tracked as `Grant` records; rotated tokens are kept as tombstones for reuse detection; revocation removes the family. Binding applies to public clients only (RFC 9449 §5), so end-to-end coverage awaits public-client support (P3.1); the enforcement path is tested directly. |
| P1.9 | New `ProviderOptions.AuthorizeIntrospection`. Unauthorised callers receive `{"active":false}`. |
| P1.10 | Endpoint and `ClientIdMetadataDocumentEnabled` option removed; P5.5 reintroduces the feature properly. |
| P1.11 | New `Client.SectorIdentifierUri`; `ProviderOptionsValidator` runs at startup (`ValidateOnStart`). Pairwise subject values change for existing deployments. |

---

## Phase 2 — Hardening

- [x] **P2.1 Client assertion validation**
  ([ClientAuthenticator.cs:121-198](../src/NetOidc.Provider/Token/ClientAuthenticator.cs#L121-L198)) —
  require `sub == iss == client_id`, `jti` replay protection, max `exp` window, restrict
  algorithms; `client_secret_jwt` must use the raw secret as the HMAC key and DCR must issue
  secrets long enough for the chosen alg. Reject requests presenting more than one auth method.
- [x] **P2.2 mTLS certificate sourcing** — only read `MtlsClientCertificateHeader` from
  configured trusted proxies (`KnownProxies`/`KnownNetworks`); for `tls_client_auth` validate
  the chain against configured trust anchors; compare subject DN using RFC 4514 normalisation;
  support multiple SAN URIs (not just the first).
- [x] **P2.3 Token endpoint `redirect_uri`** — required and exact-matched when it was present in
  the authorization request ([TokenEndpointHandler.cs:158](../src/NetOidc.Provider/Token/TokenEndpointHandler.cs#L158)).
- [x] **P2.4 UserInfo** ([UserInfoEndpointHandler.cs](../src/NetOidc.Provider/UserInfo/UserInfoEndpointHandler.cs)) —
  check revocation via the store; enforce `cnf.x5t#S256` bound tokens; reject DPoP-bound tokens
  presented with the `Bearer` scheme; require the `openid` scope; return RFC 6750 error codes.
- [x] **P2.5 Revocation cascade** — revoking a refresh token revokes access tokens from the same
  grant (RFC 7009 §2.1); add `GrantId` linkage (see P3.9).
- [x] **P2.6 CSRF** — antiforgery on device approval POST
  ([DeviceVerificationEndpointHandler.cs](../src/NetOidc.Provider/Device/DeviceVerificationEndpointHandler.cs))
  and the sample login form; user-code attempt rate limiting.
- [x] **P2.7 Resource exhaustion** — expiry sweeper for `InMemoryAdapter`, `VciService` nonces
  and the DPoP `jti` cache; rate limiting on unauthenticated endpoints (nonce, DCR, device).
- [x] **P2.8 CORS** — apply only to endpoints browsers call cross-origin (token, userinfo,
  discovery, JWKS, revocation); never to authorize/device/DCR; no `AllowAnyOrigin` default —
  derive origins from registered redirect URIs.
- [x] **P2.9 Error hygiene** — stop echoing exception messages to clients
  (e.g. VCI `ex.Message`, JWT validation messages in `error_description`); log them instead.

### Phase 2 — implementation notes (branch `fix/p2-hardening`)

All nine items are implemented with regression tests (335 tests pass). The new tests that
compile against the pre-fix code were run on `main` and fail as expected (20 of 27; the rest
cover behaviour that was already correct). Where the implementation differs from the text
above, or leaves work for a later item:

| Item | Note |
|------|------|
| P2.1 | `ClientAuthenticator` is now an injected service. New `ClientAssertionMaxLifetimeSeconds` (default 300). Basic-auth credentials are form-decoded (`+` → space). DCR secrets are 64 random bytes. |
| P2.2 | New `MtlsTrustedProxies`, `MtlsCertificateAuthorities` (empty = OS trust store) and `MtlsRevocationMode` (default `NoCheck`). A client whose method is not mTLS may present a certificate and still use its secret. `self_signed_tls_client_auth` now also checks the certificate validity period and is allowed under FAPI 2.0 (P3.13 overlap). |
| P2.3 | `AuthorizationCode.RedirectUriInRequest` records whether the value was sent. |
| P2.4 | Only the Authorization header is accepted (form-body tokens are not). Challenges follow RFC 6750 §3 / RFC 9449 §7.1. |
| P2.5 | Implemented through `AccessTokenService`: access tokens issued with a refresh token carry its grant id and die with the grant. Full grant linkage (codes, consent) remains P3.9. |
| P2.6 | The device prompt (`GET`) returns a `csrf` object; `POST` must include it. The token is bound to the signed-in identity, so hosts must fetch the prompt after login. New `DeviceUserCodeMaxFailedAttempts` / `DeviceUserCodeFailureWindowSeconds`. The sample host login form uses antiforgery. |
| P2.7 | Throttles run inside the handlers (no host middleware needed); new `UnauthenticatedRequestsPerMinute` (default 60, 0 disables) covers nonce, registration and device authorization. Stores sweep every 30 s. All in-process; distributed variants are P4.3. |
| P2.8 | Origins = `CorsAllowedOrigins` ∪ origins of static clients' redirect URIs. Dynamically registered clients are not included automatically. |
| P2.9 | Only `ClientMetadataValidationException` messages from `ValidateDynamicClient` reach clients. First `ILogger` usage in the library (DCR, JAR, jwt-bearer, VCI, back-channel logout); full logging remains P4.2. |

---

## Phase 3 — Specification conformance (OIDC Core / OAuth 2.x)

- [x] **P3.1 Public clients (`token_endpoint_auth_method=none`)** — not supported by
  `ClientAuthenticator`, so SPA/native code flow, device flow and DCR-registered public clients
  cannot reach the token endpoint. Support it, with PKCE mandatory.
- [x] **P3.2 Authorization endpoint POST** — map POST (form) as required by OIDC Core §3.1.2.1.
- [x] **P3.3 `prompt`, `max_age`, `login_hint`, `id_token_hint`, `acr_values`, `ui_locales`** — **BREAKING**
  - Redesign `IInteractionService` to receive a full `InteractionRequest` and return login
    time, acr/amr and consent state. `prompt=none` must return `login_required` /
    `consent_required` / `interaction_required` instead of redirecting.
  - Replace auto-consent in `DefaultInteractionService` with a consent store (`Grant` model).
- [x] **P3.4 ID token content** ([TokenFactory.cs](../src/NetOidc.Provider/Jose/TokenFactory.cs))
  - `at_hash` / `c_hash` for hybrid and implicit responses (required by OIDC Core §3.3.2.11).
  - `auth_time` = actual authentication time (from P3.3), not issuance time.
  - `azp` when needed; `acr` honouring `acr_values`.
  - Apply ID-token encryption at the token endpoint too (currently only in the implicit flow,
    because `client` is not passed in).
- [x] **P3.5 `claims` request parameter** — `ClaimsEngine` is dead code; wire it into the
  ID token and UserInfo (including `essential` and `value(s)`), and pass claims through JAR/PAR.
- [x] **P3.6 Pairwise subject handling** — keep the local subject in grants/sessions and map to
  pairwise only at token issuance; `FindUserClaims` must receive the local subject; sessions and
  back-channel logout must send each client its own `sub`.
- [x] **P3.7 JAR semantics** — per RFC 9101 §6.3 use only request-object parameters (plus
  `client_id`); require `request_uri` fetching or reject it explicitly; honour
  `JarRequireSignedRequestObject` (currently unused).
- [x] **P3.8 PKCE** — default to rejecting a missing `code_challenge_method` (or treat as
  `plain` only when explicitly allowed); make `plain` opt-in.
- [x] **P3.9 Grants model** — use the existing `Grant` model to link codes, access tokens and
  refresh tokens (enables P1.4 code-replay revocation, P1.8 families, P2.5 cascade).
- [x] **P3.10 Grant-type enforcement** — check `AllowedGrantTypes` for `authorization_code` and
  `refresh_token`; replace the non-standard `"hybrid"` grant with response-type allowlists on the
  client (`ResponseTypes`) — **BREAKING** `Client` model.
- [x] **P3.11 Refresh** — support `scope` downscoping; honour `IssueRefreshTokens`; optional
  ID token on refresh; configurable rotation.
- [x] **P3.12 Resource indicators** — resources must drive the access-token `aud`, be validated
  against an allowlist, and be re-requestable at the token endpoint.
- [x] **P3.13 FAPI runtime enforcement** — FAPI 2: refuse to issue unbound tokens (require DPoP
  or mTLS), allow `self_signed_tls_client_auth`; FAPI 1 Advanced: allowed auth methods are
  `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` only; require PAR/JAR
  where the profile mandates it.
- [x] **P3.14 CIBA**
  - Add a public `ICibaService.CompleteAsync(authReqId, subject, approve)` (docs reference a
    non-existent `CompleteCibaRequestAsync`).
  - Run the out-of-band hook without the request's cancellation token and observe exceptions.
  - Validate `id_token_hint`/`login_hint_token`, `requested_expiry`, `binding_message`,
    `user_code`; signed authentication requests.
  - Implement **ping** and **push** delivery modes.
- [x] **P3.15 Device flow** — increase interval on `slow_down` (RFC 8628 §3.5); consume
  approved device codes atomically; validate scopes against registered scopes.
- [x] **P3.16 Logout** — confirmation step when no valid `id_token_hint`; session lookup via the
  `netoidc.sid` cookie; session TTL; front-channel logout; `typ: logout+jwt`.

### Phase 3 — implementation notes (branch `feat/p3-conformance`)

All sixteen items are implemented with regression tests (393 tests pass) and an end-to-end
check against the sample host (login → authorize with PKCE → token → UserInfo → logout).
Most new tests depend on APIs introduced in this phase, so unlike Phases 1–2 they were not
run against `main`. Token issuance for every grant now goes through one
`TokenIssuanceService`. Differences from the text above, and follow-ups:

| Item | Note |
|------|------|
| P3.1 | Public clients authenticate by `client_id` alone and always need PKCE. They can also call introspection/revocation, where they only ever see their own tokens. |
| P3.3 | New `IInteractionService.EvaluateAsync(InteractionRequest)` contract (**BREAKING**). Consent is a new `Consent` model with `ConsentService`, not the `Grant` model: grants track token lineage, consent is per (client, subject). Suspended requests are recorded as `PendingInteraction` and resumed via an `interaction` parameter. New options: `ConsentPath`, `InteractionLifetimeSeconds`; new `Client.RequireConsent` (default **true**; DCR clients always). `login_hint`, `ui_locales` and `acr_values` are passed to the login page. |
| P3.4 | `azp` is not emitted: ID tokens always have a single audience. `acr` is whatever the interaction service reports (the default reads an `acr` claim); `acr_values` are passed to the login page. `auth_time` falls back to the auth cookie's issue time; without either, `max_age` forces a login. |
| P3.5 | `FindUserClaims` now receives a `UserClaimsRequest` (**BREAKING**) and output is filtered to claims justified by scopes (OIDC Core §5.4, or `Scope.Claims`) or the `claims` request. `value`/`values` are only enforced for an essential `acr`. |
| P3.6 | Records (codes, tokens, sessions, grants, consent) hold the local subject; pairwise `sub` is computed per client at every output (ID/access tokens, UserInfo, introspection, logout tokens). |
| P3.7 | `request_uri` by reference returns `request_uri_not_supported`; discovery advertises `request_uri_parameter_supported: false`. PAR records whether the pushed parameters came from a request object. |
| P3.9 | Each authorization creates a `Grant`; codes are kept as tombstones for the access-token lifetime so a late replay still revokes. Device/CIBA flows create their grant at redemption. |
| P3.10 | `"hybrid"` is gone: hybrid clients list `authorization_code` + `implicit` and the hybrid `ResponseTypes`. A refresh token is only issued when the client lists `refresh_token`. |
| P3.11 | New `RotateRefreshTokens` (default true); unbound public-client tokens always rotate. The token response now includes `scope`. |
| P3.12 | New `AllowedResources` (required allowlist) and `Client.AllowedResources`. Access-token `aud` = issuer + resources, so tokens stay usable at the OP's UserInfo endpoint. |
| P3.13 | FAPI 1: request object or PAR required. FAPI 2: PAR required, and the token endpoint refuses to issue unbound tokens (DPoP or mTLS). Also enforced at runtime: FAPI 2 Message Signing requires JAR + JARM, and FAPI-CIBA requires signed requests and forbids push. |
| P3.14 | `ICibaService.CompleteAsync` resolves requests; ping notifies and push delivers tokens (with `auth_req_id`, `at_hash`, `rt_hash`) to `CibaClientNotificationEndpoint` through the SSRF-safe clients. Push tokens are not sender-constrained (no proof channel). `user_code` and `login_hint_token` are passed to the host hook for verification. |
| P3.15 | `auth_time` for device grants is the approval time. |
| P3.16 | New `LogoutConfirmationPath` (host page) and `SessionLifetimeSeconds`, `FrontChannelLogoutEnabled`, `Client.FrontChannelLogoutUri`/`FrontChannelLogoutSessionRequired`. |

Bugs found and fixed while doing this phase:

- **Back-channel logout never worked:** the `events` claim could not be serialized, and the error was swallowed.
- **Resumed PAR requests failed:** a pushed `request_uri` was consumed before the login redirect, so the resumed request failed.
- **Sample host logout was missing:** logout was never enabled there, so the sample client's sign-out hit a missing endpoint.

---

## Phase 4 — Key management & operability

- [x] **P4.1 Key management** — **BREAKING**
  - Replace the ephemeral `SigningKeyProvider`/`EncryptionKeyProvider` with an `IKeyStore`
    abstraction (configured keys, X.509 certs, HSM/KMS via delegates — the `JWKSFunc`/`SignerFunc`
    equivalents promised in the implementation plan).
  - Multiple active keys with `kid` rotation and overlap; publish all verification keys in JWKS.
  - Per-client `id_token_signed_response_alg`, `authorization_signed_response_alg`, and
    EC/PS algorithms advertised in discovery.
  - Refuse to start in Production environment with auto-generated keys.
- [x] **P4.2 Logging** — no `ILogger` exists in the library. Add structured logging to every
  endpoint (no secrets/tokens), plus failure events: client auth failure, invalid grant,
  logout, device/CIBA decisions, DCR changes.
- [x] **P4.3 Distributed replay caches** — move DPoP `jti`, client-assertion `jti`, VCI
  nonces behind an `IReplayCache` adapter; support DPoP server nonces (RFC 9449 §8).
- [x] **P4.4 Options validation** — `IValidateOptions` for all options: absolute https
  `Issuer` (http only in Development), positive lifetimes, required hooks for enabled features.
- [x] **P4.5 Opaque access tokens** — offered in the implementation plan, not implemented.
- [x] **P4.6 Health/observability** — `ActivitySource` tracing and metrics (tokens issued, failures).

### Phase 4 — implementation notes (branch `feat/p4-keys-ops`)

All six items are implemented with regression tests (421 tests pass, stable over repeated
runs). The sample host was checked end to end, including its `/health` endpoint and that it
refuses to start in Production. Differences from the text above, and follow-ups:

| Item | Note |
|------|------|
| P4.1 | `SigningKeyProvider`/`EncryptionKeyProvider` are replaced by `IKeyStore` + `KeyRing` (**BREAKING**). Keys come from `AddSigningKey`, `AddSigningCertificate`, `AddEncryptionKey`, `AddKey` (HSM/KMS: a `SecurityKey` with a custom `CryptoProviderFactory` plus `PublicJwk`) or `UseKeyStore<T>()`. Rotation uses `NotBefore`/`NotAfter`: future keys are published but unused; expired keys drop out of JWKS and validation. `KeyRingStartupCheck` refuses generated keys in Production and validates algorithms, key types and `kid` uniqueness. New `Client.IdTokenSignedResponseAlg`; `AuthorizationSignedResponseAlg` is now honoured; `at_hash`/`c_hash`/`rt_hash` follow the signing algorithm. UserInfo signing (`userinfo_signed_response_alg`) remains P5.2. |
| P4.2 | Structured `LoggerMessage` logging at every endpoint (client ids, grant types and error codes only). New `IProviderEventSink` events are default interface methods, so existing sinks keep compiling. |
| P4.3 | DPoP/assertion/jwt-bearer/CIBA `jti` already used `IReplayCache`; VCI nonces now use `IAdapter<CredentialNonce>`. DPoP server nonces are stateless (HMAC + time) and need a shared `DPoPNonceSecret` across instances. No Redis/SQL adapters ship: the `IAdapter`/`IReplayCache` docs spell out the atomicity required (Redis `SET NX`/`GETDEL`). |
| P4.4 | `ProviderOptionsValidator` covers issuer, lifetimes, paths, feature prerequisites and static clients. `CibaEnabled` now requires `ProcessBackchannelAuthenticationRequest`, and `VciEnabled` requires `IssueCredential`. `JwtBearerGrantEnabled` does not require its policy: the grant stays deny-by-default. |
| P4.5 | `ProviderOptions.AccessTokenFormat` / `Client.AccessTokenFormat`. Opaque tokens are stored by SHA-256 hash; introspection now answers from the stored record for both formats. |
| P4.6 | `NetOidcTelemetry` (`ActivitySource` + `Meter` named `NetOidc.Provider`): per-endpoint traces and duration histogram, plus counters for tokens issued, failed token requests, authorizations and client-auth failures. `AddHealthChecks().AddNetOidcKeys()` reports the key state. |

---

## Phase 5 — Complete advertised features

Discovery and README currently advertise capabilities that are missing or partial.
With production readiness as the goal, these are implemented rather than removed.

- [x] **P5.1 Discovery accuracy** — generate metadata from what is actually enabled:
  `claims_parameter_supported` (after P3.5), response types per profile, auth methods incl.
  `none`, encryption algs only when supported, `backchannel_user_code_parameter_supported`
  (after P3.14), `prompt_values_supported`, `dpop_signing_alg_values_supported`. Snapshot-test it.
- [x] **P5.2 UserInfo signing/encryption** — `userinfo_signed_response_alg` /
  `userinfo_encrypted_response_*`.
- [x] **P5.3 OpenID Federation 1.1**
  ([FederationService.cs](../src/NetOidc.Provider/Federation/FederationService.cs)) — separate
  federation entity keys; correct `federation_entity` metadata (current `federation_fetch_endpoint`
  is wrong); trust-chain resolution and metadata policy; automatic and explicit registration
  (currently advertised but not implemented); reuse the discovery builder instead of the
  duplicated, divergent metadata.
- [x] **P5.4 OID4VCI 1.0 final** — `proofs` object and `credentials` array, credential offer,
  pre-authorized code grant, `authorization_details` of type `openid_credential`, deferred
  issuance, notification endpoint.
- [x] **P5.5 Client ID Metadata Document** — fetch/cache/validate metadata for URL `client_id`s
  (SSRF-safe HTTP client, size limits, cache TTL).
- [x] **P5.6 Other plan items** — attestation-based client auth, RP Metadata Choices, pluggable
  error rendering hooks.

### Phase 5 — implementation notes (branch `feat/p5-features`)

All six items are implemented with tests (521 tests pass, stable over repeated runs). The sample
host was started and its discovery, JWKS and feature endpoints checked. Outbound fetches for
federation, Client ID Metadata Documents and DCR `jwks_uri` go through `SafeHttpFetcher` (the SSRF-safe
untrusted client: https only, no redirects, public addresses only, size limits). Differences from
the text above, and follow-ups:

| Item | Note |
|------|------|
| P5.1 | Discovery follows the configuration: response and grant types per FAPI profile, FAPI-only client authentication methods, `attest_jwt_client_auth`, `token_endpoint_auth_signing_alg_values_supported`, request-object encryption only with JAR and encryption keys, UserInfo signing/encryption algorithms, `require_signed_request_object`, the pre-authorized grant and `pre-authorized_grant_anonymous_access_supported`, `openid_credential` authorization details and `client_id_metadata_document_supported`. The default document is snapshot-tested key by key. |
| P5.1 | **Fixed (BREAKING):** Microsoft.IdentityModel supports RSA-OAEP-256 neither for encryption nor decryption, and AES-GCM only for decryption. RSA-OAEP-256 (the previous generated/default encryption key algorithm) is now rejected at startup; `RSA-OAEP` is the only key-management algorithm; encryption to clients uses AES-CBC-HMAC only. Encrypted request objects never worked (the JWE was validated together with the inner signature, without the client's keys); they are now decrypted, then verified, with CBC and GCM content encryption. |
| P5.2 | `Client.UserInfoSignedResponseAlg` / `UserInfoEncryptedResponseAlg` / `UserInfoEncryptedResponseEnc` return `application/jwt`; an encrypted response is always signed first (nested JWT). The ID-token `enc` default is now `A128CBC-HS256` (OIDC Registration §2). Static clients' encryption settings are validated at startup. |
| P5.3 | Separate federation entity keys (`AddFederationKey`, generated in Development), never published in the OP JWKS. The entity configuration reuses the discovery document. `TrustChainResolver` walks `authority_hints` to a configured trust anchor (`FederationTrustAnchors`: entity id → JWKS), verifying every statement and key hand-over, and applies `metadata` and `metadata_policy` (`value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, `essential`; unknown operators reject the chain). Automatic registration resolves URL `client_id`s through the chain (`private_key_jwt`, signed request objects, consent; requires JAR); explicit registration at `FederationRegistrationEndpoint` answers with a signed `explicit-registration-response+jwt`. Registrations live until the chain expires. Not implemented: trust marks, `signed_jwks_uri`, `trust_chain` request parameter, resolve/list endpoints. |
| P5.4 | Credential offers (`CredentialOfferService.CreateAsync`, served by reference), the pre-authorized code grant with `tx_code` (attempt-limited) and optional anonymous access, `openid_credential` authorization details with `credential_identifiers`, the `credentials` array response, batch issuance (`VciBatchSize`), deferred issuance (`RetrieveDeferredCredential`) and notifications (`OnCredentialNotification`). **BREAKING:** `IssueCredential` returns `CredentialIssuanceResult` (a string converts implicitly); a configuration without `Scope` is only issued through authorization details (previously any End-User token could obtain it). Token responses now include `authorization_details` (RFC 9396 §7). Credential response encryption is refused with `invalid_encryption_parameters`. |
| P5.5 | `ClientIdMetadataDocumentEnabled`: an unknown https `client_id` with a path is fetched, validated (`client_id` must match, no secrets, `none` or `private_key_jwt`, code flow only, redirect URIs validated) and cached per `Cache-Control` (1 min–1 day). Optional host allowlist. Resolved clients always require PKCE and consent. |
| P5.6 | `RenderErrorPage` renders unredirectable authorization and logout errors. Attestation-based client authentication (`attest_jwt_client_auth`, trusted attesters in `ClientAttestationTrustedAttesters`, single-use PoP `jti`); no challenge endpoint yet. DCR accepts `jwks`/`jwks_uri` (fetched once; rotate with an update), `private_key_jwt`/`client_secret_jwt`, signing and encryption algorithms, `require_signed_request_object`, and RP Metadata Choices (`*_supported` lists; the provider picks the first value it supports; the singular parameter wins). DCR updates keep `client_id_issued_at` and the registration access token (unless rotation is on). |

---

## Phase 6 — Verification & release readiness

- [ ] **P6.1 Regression suite** — every item above has a test; add concurrency tests (P1.4) and
  negative security tests per endpoint.
- [ ] **P6.2 Conformance** — add the `NetOidc.Conformance` project from the implementation plan;
  pass the OpenID Foundation suites: Basic, Implicit, Hybrid, Config, Dynamic, RP-Initiated /
  Back-Channel Logout, FAPI 1 Advanced, FAPI 2 Security + Message Signing, FAPI-CIBA.
- [ ] **P6.3 Independent security review** of the finished Phase 1–4 work.
- [ ] **P6.4 Documentation** — adapter guide (including the atomicity contract), key management
  guide, production deployment checklist, CHANGELOG with breaking changes, accurate README
  status table.
- [ ] **P6.5 Packaging** — replace placeholder `RepositoryUrl`/`PackageProjectUrl` in
  [Directory.Build.props](../Directory.Build.props); Source Link; public API analyzers.

### Phase 6 — status (branch `release/1.0`, IN PROGRESS — paused 2026-09-30)

| Item | State |
|------|-------|
| P6.1 | Done: `ConcurrencyTests` (50 racers per single-use artifact), `EndpointNegativeTests` (auth, forged tokens, malformed input, duplicate params, methods, response hygiene), traceability to every P1–P5 item. |
| P6.2 | Harness done (`test/NetOidc.Conformance`, `run-conformance.sh`). Local results: OIDC Basic, Implicit, Hybrid, Form Post, Config — no failures; Dynamic — only `oidcc-server-rotate-keys` (expected, self-attested); FAPI 2 SP — DPoP 57/57, pkjwt+mTLS 48/48, mTLS 36/37 (1 transient network error, rerun). **Still to finish:** RP-initiated / front / back-channel logout plans (`no-id-token-hint`, `only-state` time out — check browser flow), FAPI 2 Message Signing (early errors now JARM-wrapped — rerun), FAPI 1 Advanced (rerun after PKCE harness fix), FAPI-CIBA (first run aborted — investigate). Then write `docs/CONFORMANCE.md`. |
| P6.3 | Internal review done ([SECURITY_REVIEW.md](SECURITY_REVIEW.md)); independent review still required. |
| P6.4 | Done: ADAPTERS, KEY_MANAGEMENT, PRODUCTION_CHECKLIST, SECURITY_REVIEW, CHANGELOG, README. Update README/CHANGELOG with final conformance numbers. |
| P6.5 | Done: repo URLs, Source Link + snupkg, PublicApiAnalyzers (`PublicAPI.Unshipped.txt`), public surface trimmed, CI workflow. |

**Resume here:** the last change (errors routed through `SendError` → `BuildRedirect` with `iss` and JARM)
leaves one failing unit test, `Phase7Tests.Fapi1_Authorization_Rejects_OpenId_WhenNonceMissing`
(expects `error=invalid_request` in the query; the error is now JARM-wrapped or placed differently —
inspect and fix). Then `dotnet test`, rebuild the conformance host and rerun the pending plans:
`SUITE_DIR=<suite checkout> KEEP_SUITE=1 ./run-conformance.sh fapi2-ms|fapi1|fapi-ciba|oidcc`
(use distinct `OP_URL` ports / `ALIAS` / `CONFIGURATION` to run profiles concurrently).

---

## Suggested order and branches

| Branch | Items | Notes |
|--------|-------|-------|
| `fix/p1-security` | P1.1 – P1.11 | Ship first; small, independent fixes |
| `fix/p2-hardening` | P2.1 – P2.9 | |
| `feat/p3-grants-model` | P3.9, P3.10, P1.4 follow-up, P1.8, P2.5 | Foundation for later Phase 3 items |
| `feat/p3-interaction` | P3.3, P3.4, P3.6, P3.5 | Largest breaking change |
| `feat/p3-conformance` | remaining Phase 3 | |
| `feat/p4-keys-ops` | Phase 4 | P4.1 can run in parallel with Phase 3 |
| `feat/p5-*` | Phase 5, one branch per feature | |
| `release/1.0` | Phase 6 | |
