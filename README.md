# NetOidc

> **⚠️ Pre-release — not production ready.**
> APIs may change before v1.0. Security has not been independently audited.

A configurable OAuth 2.0 / OpenID Connect provider for **.NET 8**, modeled after
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
| `test/NetOidc.Provider.Tests` | 191 xUnit integration tests |

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

## Implementation status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Foundations & scaffolding | ✅ Done |
| 1 | Core OIDC — auth-code flow, PKCE, tokens, UserInfo, discovery | ✅ Done |
| 2 | OAuth2 grants, introspection, revocation, claims engine | ✅ Done |
| 3 | DCR (RFC 7591/7592), session management, logout | ✅ Done |
| 4 | PAR, JAR, JARM, RAR, Token Exchange, JWT Bearer | ✅ Done |
| 5 | DPoP, mTLS, private_key_jwt / client_secret_jwt | ✅ Done |
| 6 | CIBA (poll), Device Authorization Grant | ✅ Done |
| 7 | FAPI 1.0 Advanced, FAPI 2.0 Security/Message Signing, FAPI-CIBA | ✅ Done |
| 8 | OpenID Federation 1.1, OID4VCI 1.0, CORS, Client ID Metadata | ✅ Done |
| 9 | Events/hooks system, NuGet packaging, security hardening | ✅ Done |

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
            AllowedGrantTypes = ["authorization_code"],
            AllowedScopes = ["openid", "profile"],
            RedirectUris = ["https://myapp.example.com/callback"],
            RequirePkce = true,
        }
    ];

    options.Scopes =
    [
        new Scope { Name = "openid" },
        new Scope { Name = "profile" },
    ];

    options.FindUserClaims = (sub, scopes, ct) =>
    {
        var claims = new Dictionary<string, object> { ["sub"] = sub };
        if (scopes.Contains("profile")) claims["name"] = "Alice";
        return Task.FromResult<IReadOnlyDictionary<string, object>>(claims);
    };
});

app.UseAuthentication();
app.MapNetOidc();
```

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
| `/connect/credential` | POST | OID4VCI 1.0 | `VciEnabled` |
| `/connect/nonce` | POST | OID4VCI 1.0 | `VciEnabled` |

## Feature flags (selected)

```csharp
options.IssueRefreshTokens = true;
options.DcrEnabled = true;
options.LogoutEnabled = true;
options.BackChannelLogoutEnabled = true;
options.PushedAuthorizationEnabled = true;
options.RequirePushedAuthorization = true;   // mandate PAR
options.JarEnabled = true;
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
options.VciEnabled = true;
options.CorsEnabled = true;
```

## Custom adapters

Implement `IAdapter<T>` to plug in any persistence backend (EF Core, Redis, etc.):

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

191 tests covering all phases: authorization code, PKCE, implicit, hybrid, client credentials, refresh tokens, introspection, revocation, DCR, logout, PAR, JAR, JARM, token exchange, JWT bearer, DPoP, mTLS, device flow, CIBA, FAPI profiles, federation, VCI, CORS, events.

## License

MIT
