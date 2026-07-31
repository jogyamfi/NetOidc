# NetOidc — Implementation Plan

A configurable OAuth 2.0 / OpenID Connect Provider for **.NET 8 (LTS)**, modeled after
[`go-oidc`](https://github.com/luikyv/go-oidc) and
[`node-oidc-provider`](https://github.com/panva/node-oidc-provider).

## Goal

Build a reusable **core library** (NuGet) that mounts into ASP.NET Core, plus a **thin
sample host app**. Protocol logic is implemented **from scratch** (only low-level
JOSE/crypto libraries). **Full parity** (FAPI 1/2, Federation, VCI, CIBA, Device, etc.) is
the end goal, delivered across phases. Storage is a **pluggable adapter interface** with an
**in-memory default**.

## Locked decisions

- **Packaging:** `NetOidc.Provider` core library + `samples/NetOidc.Sample.Host` ASP.NET Core app.
- **Implementation:** from scratch. JOSE via `Microsoft.IdentityModel.Tokens` /
  `System.Security.Cryptography` (the .NET equivalent of `go-jose`). No OpenIddict / Duende
  as the engine.
- **Scope:** full parity as the end goal, phased.
- **Persistence:** per-model `IAdapter<T>` store interface + in-memory default (mirrors
  node-oidc-provider adapters and go-oidc `goidc.*Manager` interfaces).
- **Target framework:** `net8.0`.

## Reference architecture (source repos)

- **go-oidc:** `pkg/provider` (Provider + functional `WithXxx` options), `pkg/goidc`
  (public models: Client, Grant, Token, Scope, JOSE), `internal/*` per-feature packages
  (authorize, token, dcr, dpop, discovery, federation, logout, userinfo, vc, joseutil,
  storage manager). Storage = pluggable `GrantManager`, `AuthManager`,
  `OpaqueTokenManager`, `DCRManager` interfaces + in-memory.
- **node-oidc-provider:** `lib/actions/*` (endpoint handlers: authorization, token,
  userinfo, discovery, registration, introspection, revocation, end_session,
  code_verification, challenge, credential), `lib/models/*` (Client, Grant, AccessToken,
  AuthorizationCode, RefreshToken, DeviceCode, Session, Interaction, PAR, etc.),
  `lib/helpers/*`, `lib/adapters/memory_adapter.js`, interaction policy, response_modes.

## Target solution layout

```
net-oidc/
  NetOidc.sln
  Directory.Build.props
  src/
    NetOidc.Provider/             # core library (NuGet)
      Configuration/              # ProviderOptions, feature toggles, profiles, DI builder
      Models/                     # Client, Grant, Token, Scope, Session, Interaction...
      Endpoints/                  # endpoint handlers (node "actions" equivalent)
      Grants/                     # grant-type handlers
      Jose/                       # signing/encryption/JWKS abstractions
      Adapters/                   # IAdapter<T> + InMemoryAdapter
      ResponseModes/              # query, fragment, form_post, jwt (JARM)
      Claims/                     # claim sourcing, filtering, id_token/userinfo assembly
      Discovery/                  # metadata document builder
      Interaction/                # interaction/consent policy engine
      Http/                       # ASP.NET Core middleware/endpoint routing, DI extensions
      Errors/                     # OAuth/OIDC error types + rendering
    NetOidc.Provider.Abstractions/ # public interfaces & model contracts (adapter-facing)
  samples/
    NetOidc.Sample.Host/          # minimal ASP.NET Core host wiring the provider
  test/
    NetOidc.Provider.Tests/       # xUnit unit + integration (WebApplicationFactory)
    NetOidc.Conformance/          # optional: harness for OIDC conformance suite
  docs/
    IMPLEMENTATION_PLAN.md
```

## Phases

### Phase 0 — Foundations & scaffolding

- Create `NetOidc.sln`, `src/NetOidc.Provider` (net8.0 classlib), `samples/NetOidc.Sample.Host`,
  `test/NetOidc.Provider.Tests` (xUnit).
- Add deps: `Microsoft.IdentityModel.Tokens`, `Microsoft.IdentityModel.JsonWebTokens`,
  `System.Text.Json`. Set up `Directory.Build.props`, `nullable enable`, analyzers, CI stub.
- Define `ProviderOptions` + fluent/DI `AddNetOidc(...)` builder (functional-options
  equivalent). Define `IAdapter<T>` + `InMemoryAdapter`. Define core models: `Client`,
  `Grant`, `AccessToken`/`Token`, `Scope`.
- ASP.NET Core integration: `MapNetOidc()` endpoint routing + middleware pipeline.
- **Verify:** solution builds; sample host boots; unit test project runs.

### Phase 1 — Core OIDC (MVP certifiable Basic OP)

- Discovery: `/.well-known/openid-configuration` + JWKS endpoint (RFC 8414 + OIDC Discovery).
- Authorization endpoint: authorization_code flow, `response_type=code`, redirect_uri
  validation, state/nonce, PKCE (RFC 7636).
- Token endpoint: authorization_code grant, client auth (`client_secret_basic`,
  `client_secret_post`), access token (JWT RFC 9068 + opaque), refresh_token grant.
- ID Token issuance + signing (RS256 default). UserInfo endpoint.
- Interaction/consent redirect model (login + consent) with pluggable policy.
- Response modes: query, fragment, form_post.
- Static client configuration.
- **Verify:** e2e auth-code + PKCE test; discovery-doc snapshot; target OIDC Basic OP
  conformance.

### Phase 2 — OAuth2 grants & token management

- Grants: client_credentials, implicit, hybrid, refresh rotation.
- Token Introspection (RFC 7662), Token Revocation (RFC 7009).
- Scopes/claims mapping engine, `claims` request param, ACR/AMR, sub identifier types
  (public/pairwise).
- Issuer identification (RFC 9207), Native Apps considerations (RFC 8252).
- **Verify:** introspection/revocation tests; Implicit/Hybrid/Config OP conformance.

### Phase 3 — Dynamic Client Registration & sessions/logout

- DCR + DCM (RFC 7591/7592, OIDC Registration): register/read/update/delete, registration
  access tokens, initial access tokens, pluggable handle/validate hooks.
- RP-Initiated Logout, Back-Channel Logout, Session management + `Session` model.
- **Verify:** DCR CRUD tests; logout conformance.

### Phase 4 — Request/response security extensions

- PAR (RFC 9126), JAR (RFC 9101, signed/encrypted request objects), JARM response mode.
- Resource Indicators (RFC 8707), Rich Authorization Requests (RFC 9396), Token Exchange
  (RFC 8693), JWT Bearer grant.
- JOSE encryption (id_token/userinfo/request object enc), full alg negotiation.
- **Verify:** PAR/JAR/JARM integration tests.

### Phase 5 — Sender-constrained tokens & advanced auth

- DPoP (RFC 9449), Mutual TLS client auth + certificate-bound tokens (RFC 8705).
- Client auth methods: `private_key_jwt`, `client_secret_jwt`, `tls_client_auth`,
  `self_signed_tls_client_auth`, attestation-based (draft).
- **Verify:** DPoP proof + `cnf` binding tests; mTLS thumbprint tests.

### Phase 6 — Async & decoupled flows

- CIBA (poll/ping/push), Device Authorization Grant (RFC 8628) + user-code verification UI.
- **Verify:** CIBA + device flow conformance.

### Phase 7 — FAPI profiles

- FAPI 1.0 Advanced profile, FAPI 2.0 Security Profile, FAPI 2.0 Message Signing, FAPI-CIBA.
- Profile system that tightens defaults + config validation (mirrors go-oidc `WithProfile`
  + profile validation).
- **Verify:** FAPI 1.0 / FAPI 2.0 conformance suites.

### Phase 8 — Federation & Verifiable Credentials

- OpenID Federation 1.1 (+ Connect), entity statements, trust chains.
- OpenID for Verifiable Credential Issuance 1.0 (credential + nonce endpoints).
- RP Metadata Choices, Client ID Metadata Document (draft), CORS handling.
- **Verify:** federation trust-chain tests; VCI issuance test.

### Phase 9 — Hardening, docs, packaging

- Events/hooks system (node emits events), extensibility review, security review
  (OWASP Top 10), perf pass, adapter guides.
- NuGet packaging + versioning, full docs, sample host expansion.
- **Verify:** full conformance matrix; security checklist; publish dry-run.

## Cross-cutting design notes

- **Options/config:** single `ProviderOptions` graph + DI builder + per-feature toggles;
  port go-oidc `internal/oidc/config.go` fields and node `configuration.js` defaults.
- **Storage:** per-model `IAdapter<T>` (node style) with in-memory default;
  encryptable/rotatable records.
- **Errors:** typed OAuth error hierarchy + pluggable render/handle hooks (both repos have
  this).
- **JOSE:** wrap `Microsoft.IdentityModel` for sign/verify/encrypt; `JWKSFunc`/`SignerFunc`
  equivalents so keys can be externally sourced (HSM/KMS).
- **Testing:** xUnit + `WebApplicationFactory` integration tests; snapshot discovery docs;
  optional `NetOidc.Conformance` project driving the OpenID conformance suite (both upstreams
  are certified — parity target).

## Open considerations (recommendations)

1. **Adapter shape:** per-model `IAdapter<T>` (node) vs grouped managers (go).
   *Recommendation: per-model.*
2. **Interaction UI:** ship headless redirect contract only; sample host provides views.
   *Recommendation: headless + sample views.*
3. **Split `NetOidc.Provider.Abstractions`?** *Recommendation: yes — keep public contracts
   stable for adapters.*
4. **JOSE library:** `Microsoft.IdentityModel.Tokens` (Wilson) vs pure
   `System.Security.Cryptography`. *Recommendation: Wilson — still low-level, less to
   reimplement.*
