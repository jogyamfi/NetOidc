# Production deployment checklist

Work through this list before exposing a NetOidc provider to real users. Items marked
**(enforced)** are checked at startup: the host refuses to start when they are wrong.

## Issuer and transport

- [ ] `Issuer` is the final public https URL, with no query or fragment **(enforced)**. It never
      changes after launch: relying parties pin it.
- [ ] TLS terminates with a valid certificate, TLS 1.2+ only, HSTS enabled on the host. For FAPI,
      TLS 1.2 must be limited to the BCP 195 cipher suites (`ECDHE-RSA/ECDSA-AES-GCM`), or use TLS 1.3
      only; the conformance suite tests this.
- [ ] Behind a reverse proxy, configure `ForwardedHeadersOptions` with `KnownProxies` /
      `KnownNetworks` so the request scheme and client IP are correct. Rate limiting and mTLS
      depend on the client IP.
- [ ] For mTLS (`MtlsEnabled`) behind a proxy, set `MtlsClientCertificateHeader` **and**
      `MtlsTrustedProxies`; the header is ignored from any other peer. Set
      `MtlsCertificateAuthorities` for `tls_client_auth`, and consider `MtlsRevocationMode`.

## Keys and secrets

- [ ] Signing keys are configured, not generated **(enforced in Production)**; see
      [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).
- [ ] An RS256 key is present if you serve OpenID Connect relying parties generally; PS256 or
      ES256 for FAPI.
- [ ] A rotation procedure is written down and rehearsed (publish early, switch, retire).
- [ ] `AddHealthChecks().AddNetOidcKeys()` is wired to your monitoring.
- [ ] Static client secrets are long random values (at least 32 bytes; 64 for `client_secret_jwt`
      with HS512) and come from a secret store, not source control.
- [ ] With pairwise subjects, `PairwiseSalt` is at least 32 bytes and treated as permanent **(enforced)**.
- [ ] With DPoP nonces, `DPoPNonceSecret` is set and identical on every instance.
- [ ] ASP.NET Core Data Protection keys are persisted and shared across instances (cookies,
      antiforgery tokens).

## Storage and scale-out

- [ ] Every `IAdapter<T>` and `IReplayCache` is backed by a shared store when running more than one
      instance or when state must survive restarts; see [ADAPTERS.md](ADAPTERS.md).
- [ ] The adapters pass the atomicity checks in ADAPTERS.md (single-use `ConsumeAsync`, atomic
      `TryAddAsync`).
- [ ] Store TTLs are enabled so expired records are removed.
- [ ] Grants are never evicted before their tokens expire (removing a grant revokes its tokens).

## Clients and features

- [ ] Only the features you use are enabled; discovery advertises exactly what is enabled.
- [ ] Third-party clients keep `RequireConsent = true` (the default); a consent page exists at
      `ConsentPath`.
- [ ] Public clients (SPA, native) use `token_endpoint_auth_method = none`; PKCE is then
      mandatory. Leave `AllowPlainPkce` off.
- [ ] Redirect URIs are exact https URLs (loopback/private-use schemes only for native apps).
- [ ] Dynamic registration: set `InitialAccessToken` unless open registration is intended; keep
      `DcrAllowedGrantTypes` minimal and `DcrAllowPrivateNetworkUris = false`.
- [ ] Token lifetimes suit your risk: defaults are 60 s codes, 1 h access and ID tokens, 24 h
      refresh tokens, with refresh-token rotation on.
- [ ] Token exchange and the JWT-bearer grant stay disabled unless their policy hooks
      (`AuthorizeTokenExchange`, `AuthorizeJwtBearerSubject`) are written and reviewed.
- [ ] Introspection callers are restricted with `AuthorizeIntrospection` if resource servers
      introspect tokens issued to other clients.
- [ ] With `FapiProfile` set, enable `FapiProfileValidationEnabled` so the configuration is
      checked against the profile at startup.
- [ ] CORS: only the origins that need browser access are listed (`CorsAllowedOrigins`); the
      origins of static clients' redirect URIs are added automatically.

## Host pages

- [ ] The login page validates antiforgery tokens and redirects only to local `returnUrl`s.
- [ ] The login page sets `auth_time` (or relies on the authentication ticket's issue time) so
      `max_age` and `prompt=login` work; set `acr`/`amr` claims if you use them.
- [ ] `RenderErrorPage` renders a user-facing page for errors that cannot go back to the client
      (unknown client, unregistered redirect URI, invalid logout request).
- [ ] The logout confirmation page (`LogoutConfirmationPath`) posts back with an antiforgery token.
- [ ] Session cookies are `Secure`, `HttpOnly`, and `SameSite=None` only if front-channel logout
      or `form_post` across sites needs it.

## Operations

- [ ] Logs are collected; they contain client ids, grant types and error codes, never tokens or
      secrets. Review your own event sink for the same property.
- [ ] Traces and metrics from `NetOidc.Provider` (ActivitySource and Meter) are exported.
- [ ] Alerts on: client authentication failures, `invalid_grant` spikes (code or refresh-token
      replay revokes grants), key health.
- [ ] `UnauthenticatedRequestsPerMinute` (default 60 per client IP) suits your traffic; add
      edge rate limiting for the token and authorization endpoints as well.
- [ ] Clocks are synchronised (NTP); tolerances for DPoP, assertions and request objects are small.
- [ ] The OpenID conformance suites for the profiles you advertise have passed against this
      configuration (`test/NetOidc.Conformance`).
