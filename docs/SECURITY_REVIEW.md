# Security review — Phase 6 (internal)

**Status:** internal review complete; **an independent review is still required** before 1.0
(REMEDIATION_PLAN P6.3). This document is the starting point for that reviewer: what was
examined, what was found and fixed, and what remains open.

- Date: 2026-09-30, branch `release/1.0`
- Reviewer: the project maintainers (not independent of the implementation)
- Method: code reading of the Phase 1–4 security fixes and the surrounding request handling,
  a negative test matrix applied to every endpoint, concurrency tests for single-use artifacts,
  and runs of the OpenID Foundation conformance suite (see [CONFORMANCE.md](CONFORMANCE.md)).

## Scope

| Area | Files |
|------|-------|
| Client authentication | `Token/ClientAuthenticator.cs`, `Token/ClientAttestationValidator.cs` |
| Token endpoint and grants | `Token/TokenEndpointHandler.cs`, `Token/RefreshTokenService.cs`, `Token/GrantService.cs` |
| Authorization endpoint, PAR, JAR | `Authorization/AuthorizationEndpointHandler.cs`, `Par/ParEndpointHandler.cs`, `Jose/RequestObjectValidator.cs` |
| Sender constraint | `DPoP/DPopProofValidator.cs`, mTLS in `ClientAuthenticator` |
| Token validation | `Jose/TokenFactory.cs`, `UserInfo/UserInfoEndpointHandler.cs`, `Token/IntrospectionEndpointHandler.cs` |
| Outbound requests (SSRF) | `Http/NetworkAddressPolicy.cs`, `Http/SafeHttpFetcher.cs`, HTTP client registration |
| Request parsing and responses | all endpoints (`Http/ProtocolRequestFilter.cs`) |
| Keys | `Jose/KeyRing.cs`, `Jose/ConfiguredKeyStore.cs`, `Jose/KeyRingStartupCheck.cs` |

## Findings

Every finding below has a regression test that fails without the fix
(`SecurityReviewTests`, `EndpointNegativeTests`, `ConformanceSuiteFindingsTests`).

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 1 | Medium | A malformed `request` object (e.g. `a.b.c`) threw from `new JsonWebToken(...)` and returned 500 at the authorization, PAR and CIBA endpoints — an unauthenticated crash path | Parsing failures return `invalid_request_object` |
| 2 | Medium | Access tokens (`at+JWT`) and logout tokens were accepted where an ID token is expected: `id_token_hint` and token exchange with `subject_token_type=id_token` (token type confusion) | ID tokens must carry `typ: JWT` |
| 3 | Medium | `client_secret_expires_at` was issued by DCR but never enforced | Expired secrets fail `client_secret_basic`, `client_secret_post` and `client_secret_jwt` |
| 4 | Medium | The HTTP client used for untrusted URLs honoured a configured proxy, which would resolve and connect to internal hosts on the provider's behalf, bypassing the address check | `UseProxy = false` |
| 5 | Low | IPv6 addresses embedding IPv4 (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, IPv4-compatible `::/96`, Teredo) and documentation/discard ranges were treated as public | Classified by the embedded address or refused |
| 6 | Medium | FAPI 2.0: client assertions accepted any of several audiences (audience-injection advisory, 2025) | Under FAPI 2.0 the issuer string is the only accepted `aud` |
| 7 | Medium | FAPI profiles accepted RS256 client assertions, request objects and DPoP proofs, and request objects without `nbf`/`exp` or living over 60 minutes | PS256/ES256 only; `nbf`/`exp` required and bounded |
| 8 | Low | Undecodable form bodies (`%00`) returned 500 at every form endpoint | `invalid_request` |
| 9 | Low | Repeated parameters were silently joined with a comma (`StringValues.ToString()`), e.g. two `grant_type`s | Rejected with `invalid_request` (RFC 6749 §3.1); `resource`/`audience` stay repeatable |
| 10 | Low | Token and error responses lacked `Cache-Control: no-store` (RFC 6749 §5.1) | Added to every protocol response except public metadata |
| 11 | Low | DPoP proofs were accepted with RSA keys under 2048 bits, and `htu` matched the path case-insensitively | RSA keys must be ≥ 2048 bits; the path is compared exactly (scheme and host still case-insensitive) |
| 12 | Info | ~60 implementation types (endpoint handlers, key ring, validators) were public, widening the supported surface and letting hosts bypass invariants | Made internal; the public API is tracked by an analyzer |

## Residual risks and notes for the independent reviewer

- **Refresh-token reuse detection race.** With rotation, two concurrent presentations of the same
  refresh token yield exactly one success, but the loser is not recognised as *reuse* (the
  tombstone is written after consumption), so the family is not revoked in that narrow window.
  Detection requires an adapter-level compare-and-swap; the current behaviour is safe (no double
  issuance) but less strict than RFC 9700 §4.14.2 suggests.
- **Authorization code tombstones** live for the access-token lifetime. A replay after that no
  longer revokes refresh tokens issued from the code.
- **DPoP `htu` comparison** still tolerates a trailing slash.
- **Request objects under non-FAPI profiles** are not bounded in lifetime beyond `exp`.
- **UserInfo** accepts the access token only in the `Authorization` header (a deliberate choice,
  P2.4); RFC 6750 §2.2 form-body tokens are refused, which the conformance suite reports as a
  warning.
- **Host responsibilities** — the login, consent and logout pages, `RenderErrorPage`, cookie
  settings and Data Protection are the host's. The sample and conformance hosts show safe
  patterns (antiforgery, local `returnUrl` only), but hosts are not reviewed by the library.
- **Adapters** — the atomicity contract (`ConsumeAsync`, `TryAddAsync`) is documented and tested
  for the in-memory stores only. Every production adapter must be checked
  ([ADAPTERS.md](ADAPTERS.md)).

## Suggested focus for the independent review

1. Client authentication and FAPI profile enforcement (`ClientAuthenticator`, `FapiProfileValidator`).
2. Grant lineage and revocation: codes, refresh-token families, token exchange, CIBA and device flows.
3. JOSE handling: algorithm allowlists, `typ` checks, JWE decryption of request objects, key selection.
4. OpenID Federation trust-chain resolution and metadata policy (`TrustChainResolver`, `MetadataPolicy`).
5. OID4VCI proof validation, nonces and pre-authorized codes.
6. SSRF controls for every outbound fetch (federation, CIMD, DCR `jwks_uri`, logout and CIBA notifications).
