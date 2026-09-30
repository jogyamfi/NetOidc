# NetOidc

> **Release candidate (0.9).** The security remediation and conformance work (Phases 1–6 of the
> [remediation plan](docs/REMEDIATION_PLAN.md)) is complete and the OpenID Foundation conformance
> suites run locally ([results](docs/CONFORMANCE.md)). Before 1.0: an **independent security
> review** ([scope](docs/SECURITY_REVIEW.md)) and formal certification. The public API may still
> change until then.

A configurable OAuth 2.0 / OpenID Connect provider for **.NET 10**, modeled after
[go-oidc](https://github.com/luikyv/go-oidc) and
[node-oidc-provider](https://github.com/panva/node-oidc-provider).

## Packages

| Package | Version | Description |
|---------|---------|-------------|
| `NetOidc.Provider` | 0.9.0 | Core library — endpoints, JOSE, adapters, DI |
| `NetOidc.Provider.Abstractions` | 0.9.0 | Public interfaces & model contracts (adapter-facing) |

## Solution layout

| Project | Description |
|---------|-------------|
| `src/NetOidc.Provider` | Core library |
| `src/NetOidc.Provider.Abstractions` | Public interfaces & models |
| `samples/NetOidc.Sample.Host` | Minimal ASP.NET Core host — runs the provider on port 5001 |
| `samples/NetOidc.Sample.Client` | Razor Pages relying party — connects via `AddOpenIdConnect` on port 3000 |
| `test/NetOidc.Provider.Tests` | xUnit unit and integration tests |
| `test/NetOidc.Conformance` | OP host and scripts for the OpenID Foundation conformance suite |

## Running the samples end-to-end

The two sample projects form a working OIDC pair. Start the provider first, then the client:

```bash
# terminal 1 — provider (http://localhost:5001)
dotnet run --project samples/NetOidc.Sample.Host

# terminal 2 — relying party (http://localhost:3000)
dotnet run --project samples/NetOidc.Sample.Client
```

Open `http://localhost:3000`, click **Sign in via NetOidc**, and log in as `alice` / `password123`.
The client's Profile page displays the identity claims and the raw UserInfo endpoint response.
See [`samples/NetOidc.Sample.Client/README.md`](samples/NetOidc.Sample.Client/README.md) for full details.

## Status

| Area | Status |
|------|--------|
| OpenID Connect Core, Discovery, Dynamic Registration, Session/RP-Initiated, Front- and Back-Channel Logout | Implemented; conformance suites run locally |
| OAuth 2.0 grants, PKCE, PAR, JAR, JARM, RAR, Resource Indicators, Token Exchange, JWT Bearer | Implemented |
| DPoP, mTLS (`tls_client_auth`, `self_signed_tls_client_auth`), `private_key_jwt`, `client_secret_jwt`, attestation-based client auth | Implemented |
| Device Authorization Grant, CIBA (poll, ping, push) | Implemented |
| FAPI 1.0 Advanced, FAPI 2.0 Security Profile and Message Signing, FAPI-CIBA | Implemented; conformance suites run locally |
| OpenID Federation 1.1 (trust chains, metadata policy, automatic and explicit registration) | Implemented; trust marks and resolve endpoint not yet |
| OpenID for Verifiable Credential Issuance 1.0 | Implemented |
| Remediation plan Phases 1–5 | Complete |
| Phase 6 — verification and release readiness | Regression suite, conformance harness, internal security review, documentation and packaging complete; **independent review pending** |

Per-plan conformance results: [docs/CONFORMANCE.md](docs/CONFORMANCE.md).

## Documentation

| Guide | Contents |
|-------|----------|
| [Production checklist](docs/PRODUCTION_CHECKLIST.md) | What to configure and verify before going live |
| [Key management](docs/KEY_MANAGEMENT.md) | Signing, encryption and federation keys; rotation; vault/HSM/KMS |
| [Storage adapters](docs/ADAPTERS.md) | Implementing `IAdapter<T>` and `IReplayCache`, including the atomicity contract |
| [Conformance](docs/CONFORMANCE.md) | OpenID Foundation suite results and how to reproduce them |
| [Security review](docs/SECURITY_REVIEW.md) | Internal review findings and residual risks |
| [Changelog](CHANGELOG.md) | Changes and breaking changes |

## Quick start

```csharp
// Program.cs
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o => o.LoginPath = "/account/login");

builder.Services.AddNetOidc(options =>
{
    options.Issuer = "https://auth.example.com";
    options.LoginPath = "/account/login";

    options.StaticClients =
    [
        new Client
        {
            ClientId = "my-app",
            ClientSecret = "secret",
            AllowedGrantTypes = ["authorization_code", "refresh_token"],
            AllowedScopes = ["openid", "profile"],
            RedirectUris = ["https://myapp.example.com/callback"],
            RequirePkce = true,
            // First-party app; third-party clients should keep the default consent step.
            RequireConsent = false,
        }
    ];

    options.Scopes =
    [
        new Scope { Name = "openid" },
        new Scope { Name = "profile" },
    ];

    // Return what you know about the user; only claims released by the granted scopes
    // (or requested with the claims parameter) reach the client.
    options.FindUserClaims = (request, ct) =>
        Task.FromResult<IReadOnlyDictionary<string, object>>(
            new Dictionary<string, object> { ["name"] = "Alice" });
});

app.UseAuthentication();
app.MapNetOidc();
```

## Production configuration

Without configured keys the provider generates them at startup, which only suits development:
tokens do not survive restarts or span instances, and a **Production host refuses to start**.

```csharp
builder.Services.AddNetOidc(options => { /* … */ })
    // Signing keys: register the successor with a future notBefore to publish it ahead of use.
    .AddSigningCertificate(signingCertificate)                       // RS256 by default
    .AddSigningKey(new ECDsaSecurityKey(ecKey), "ES256", notBefore: rotationDate)
    // Decrypts request objects encrypted to the provider (RSA-OAEP).
    .AddEncryptionKey(new RsaSecurityKey(rsaKey))
    // Signs the OpenID Federation entity configuration (only when FederationEnabled).
    .AddFederationKey(new RsaSecurityKey(federationKey));
    // Or source keys from a vault/HSM/KMS: .UseKeyStore<MyKeyStore>()
```

When running more than one instance, also replace the in-memory `IAdapter<T>` stores and
`IReplayCache` with shared implementations, and set `DPoPNonceSecret` if DPoP nonces are enabled.

Observability: traces and metrics are published under `NetOidc.Provider`
(`.AddSource("NetOidc.Provider")` / `.AddMeter("NetOidc.Provider")` in OpenTelemetry), and
`builder.Services.AddHealthChecks().AddNetOidcKeys()` reports the key state.

## Endpoints

| Endpoint | Method | Spec | Feature flag |
|----------|--------|------|--------------|
| `/.well-known/openid-configuration` | GET | RFC 8414 | always on |
| `/.well-known/jwks.json` | GET | OIDC Discovery | always on |
| `/connect/authorize` | GET | RFC 6749 / OIDC Core | always on |
| `/connect/token` | POST | RFC 6749 | always on |
| `/connect/userinfo` | GET, POST | OIDC Core §5.3 | always on |
| `/connect/introspect` | POST | RFC 7662 | always on |
| `/connect/revoke` | POST | RFC 7009 | always on |
| `/connect/end_session` | GET, POST | OIDC Session | `LogoutEnabled` |
| `/connect/register` | POST / GET / PUT / DELETE | RFC 7591/7592 | `DcrEnabled` |
| `/connect/par` | POST | RFC 9126 | `PushedAuthorizationEnabled` |
| `/connect/device_authorization` | POST | RFC 8628 | `DeviceFlowEnabled` |
| `/connect/device` | GET, POST | RFC 8628 | `DeviceFlowEnabled` |
| `/connect/ciba` | POST | OIDC CIBA | `CibaEnabled` |
| `/.well-known/openid-federation` | GET | OpenID Federation 1.1 | `FederationEnabled` |
| `/.well-known/openid-credential-issuer` | GET | OID4VCI 1.0 | `VciEnabled` |
| `/connect/federation_registration` | POST | OpenID Federation 1.1 (explicit registration) | `FederationEnabled` |
| `/connect/credential` | POST | OID4VCI 1.0 | `VciEnabled` |
| `/connect/nonce` | POST | OID4VCI 1.0 | `VciEnabled` |
| `/connect/credential_offer/{id}` | GET | OID4VCI 1.0 | `VciEnabled` |
| `/connect/deferred_credential` | POST | OID4VCI 1.0 | `RetrieveDeferredCredential` set |
| `/connect/notification` | POST | OID4VCI 1.0 | `OnCredentialNotification` set |

## Feature flags (selected)

```csharp
options.IssueRefreshTokens = true;
options.DcrEnabled = true;
options.LogoutEnabled = true;
options.BackChannelLogoutEnabled = true;
options.PushedAuthorizationEnabled = true;
options.RequirePushedAuthorization = true;   // mandate PAR
options.JarEnabled = true;
options.RequestUriParameterSupported = true; // request_uri by reference (pre-registered request_uris)
options.JarmEnabled = true;
options.ResourceIndicatorsEnabled = true;
options.RichAuthorizationRequestsEnabled = true;
options.TokenExchangeEnabled = true;
options.DPoPEnabled = true;
options.MtlsEnabled = true;
options.DeviceFlowEnabled = true;
options.CibaEnabled = true;
options.FapiProfile = FapiProfile.Fapi2Security;
options.FederationEnabled = true;
options.FederationTrustAnchors["https://ta.example.org"] = trustAnchorJwksJson;
options.VciEnabled = true;
options.VciPreAuthorizedAnonymousAccess = true;
options.ClientIdMetadataDocumentEnabled = true;
options.ClientAttestationTrustedAttesters["https://attester.example.com"] = attesterJwksJson;
options.CorsEnabled = true;
```

Credential issuance (OID4VCI) is driven by hooks; offers are created by the host after it has
authenticated the End-User:

```csharp
options.IssueCredential = async (request, ct) =>
    CredentialIssuanceResult.Issued([.. request.HolderPublicJwks.Select(jwk => MyIssuer.Sign(request, jwk))]);

var offer = await app.Services.GetRequiredService<CredentialOfferService>().CreateAsync(new()
{
    CredentialConfigurationIds = ["UniversityDegree"],
    PreAuthorizedSubject = userId,
    TxCode = new TxCodeOptions(Length: 6),   // deliver offer.TxCode to the End-User out of band
});
// Render offer.OfferUri (openid-credential-offer://…) as a QR code.
```

## Custom adapters

Implement `IAdapter<T>` to plug in any persistence backend (EF Core, Redis, etc.). `ConsumeAsync`
**must be atomic** — see [docs/ADAPTERS.md](docs/ADAPTERS.md) for the full contract:

```csharp
public class MyGrantAdapter : IAdapter<Grant>
{
    public Task<Grant?> FindAsync(string id, CancellationToken ct) { ... }
    public Task StoreAsync(string id, Grant entity, TimeSpan? expiresIn, CancellationToken ct) { ... }
    public Task RemoveAsync(string id, CancellationToken ct) { ... }
    public Task<Grant?> ConsumeAsync(string id, CancellationToken ct) { ... }
}

// Register before AddNetOidc so TryAdd does not override it:
builder.Services.AddSingleton<IAdapter<Grant>, MyGrantAdapter>();
builder.Services.AddNetOidc(options => { ... });
```

The default store for all models is an in-memory adapter (`InMemoryAdapter<T>`). Client storage uses `IClientStore` / `IDynamicClientStore`.

## Events / hooks

Register a custom `IProviderEventSink` to observe provider lifecycle events:

```csharp
builder.Services.AddNetOidc(options => { ... })
    .AddEventSink<MyEventSink>();

public class MyEventSink : IProviderEventSink
{
    public Task TokenIssuedAsync(TokenIssuedEvent e, CancellationToken ct = default)
    {
        Console.WriteLine($"Token issued: {e.ClientId} / {e.GrantType}");
        return Task.CompletedTask;
    }

    public Task AuthorizationSucceededAsync(AuthorizationSucceededEvent e, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task TokenIntrospectedAsync(TokenIntrospectedEvent e, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task TokenRevokedAsync(TokenRevokedEvent e, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task UserInfoRequestedAsync(UserInfoRequestedEvent e, CancellationToken ct = default)
        => Task.CompletedTask;
}
```

## Running the sample

```
cd samples/NetOidc.Sample.Host
dotnet run
```

The provider starts at `http://localhost:5001`. Demo credentials: `alice` / `password123`.

## Running the tests

```
dotnet test
```

650+ tests covering all phases, plus concurrency and per-endpoint negative security tests: authorization code, PKCE, implicit, hybrid, client credentials, refresh tokens, introspection, revocation, DCR (including RP Metadata Choices), logout, PAR, JAR (signed and encrypted), JARM, token exchange, JWT bearer, DPoP, mTLS, attestation-based client auth, device flow, CIBA, FAPI profiles, federation trust chains and registration, OID4VCI (offers, pre-authorized codes, deferred issuance, notifications), Client ID Metadata Documents, signed/encrypted UserInfo, discovery snapshot, CORS, events.

The OpenID Foundation conformance suites run locally in Docker against a dedicated host:

```
cd test/NetOidc.Conformance
./run-conformance.sh oidcc      # or fapi2, fapi2-ms, fapi1, fapi-ciba
```

See [test/NetOidc.Conformance/README.md](test/NetOidc.Conformance/README.md).

## License

MIT
