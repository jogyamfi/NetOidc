# NetOidc

> **⚠️ Work in progress — not production ready.**
> This library is under active development. APIs are unstable and security has not been audited.

A configurable OAuth 2.0 / OpenID Connect provider for **.NET 8**, modeled after
[go-oidc](https://github.com/luikyv/go-oidc) and
[node-oidc-provider](https://github.com/panva/node-oidc-provider).

## What's here

| Project | Description |
|---------|-------------|
| `src/NetOidc.Provider` | Core library — endpoints, JOSE, adapters |
| `src/NetOidc.Provider.Abstractions` | Public interfaces & model contracts |
| `samples/NetOidc.Sample.Host` | Minimal ASP.NET Core host |
| `test/NetOidc.Provider.Tests` | xUnit unit + integration tests |

## Current status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Foundations & scaffolding | ✅ Done |
| 1 | Core OIDC — auth-code flow, PKCE, tokens, UserInfo, discovery | ✅ Done |
| 2 | OAuth2 grants, introspection, revocation | 🔲 Planned |
| 3 | DCR, session management, logout | 🔲 Planned |
| 4 | PAR, JAR, JARM, RAR | 🔲 Planned |
| 5 | DPoP, mTLS, advanced client auth | 🔲 Planned |
| 6 | CIBA, Device Authorization Grant | 🔲 Planned |
| 7 | FAPI 1.0 / 2.0 profiles | 🔲 Planned |
| 8 | OpenID Federation, Verifiable Credentials | 🔲 Planned |
| 9 | Hardening, docs, NuGet packaging | 🔲 Planned |

## Quick start

```csharp
// Program.cs
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie();

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

## Running the sample

```
cd samples/NetOidc.Sample.Host
dotnet run
```

The provider starts at `http://localhost:5001`. Demo credentials: `alice` / `password123`.

Endpoints:

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /connect/authorize`
- `POST /connect/token`
- `GET /connect/userinfo`

## Running the tests

```
dotnet test
```

## License

MIT
