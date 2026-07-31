# NetOidc.Sample.Client

An ASP.NET Core Razor Pages app that acts as an OIDC **relying party**, connecting to the
NetOidc provider (`NetOidc.Sample.Host`) via `AddOpenIdConnect`.

## What it demonstrates

- `AuthenticationBuilder.AddOpenIdConnect` wired to the NetOidc provider
- Authorization code flow with PKCE (enabled by default in the middleware)
- Cookie session backed by the ID token
- Fetching claims from the UserInfo endpoint (`GetClaimsFromUserInfoEndpoint = true`)
- Calling the UserInfo endpoint directly with the saved access token
- RP-initiated logout (signs out of both the cookie and the OIDC session)

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8)
- The `NetOidc.Sample.Host` provider running on `http://localhost:5001`

## Running

### 1 — Start the provider

From the repo root:

```bash
dotnet run --project samples/NetOidc.Sample.Host
```

The provider listens on `http://localhost:5001` and has `sample-client` pre-registered with
the redirect URI `http://localhost:3000/callback`.

### 2 — Start the client

In a second terminal, from the repo root:

```bash
dotnet run --project samples/NetOidc.Sample.Client
```

The client listens on `http://localhost:3000`.

### 3 — Try it out

1. Open `http://localhost:3000` in a browser.
2. Click **Sign in via NetOidc** — you are redirected to the provider's login page.
3. Log in with the demo credentials: **`alice` / `password123`**.
4. After redirect back, the **Profile** page shows:
   - All identity claims from the ID token and UserInfo endpoint.
   - The raw JSON response from a direct `GET /userinfo` call using the access token.
5. Click **Sign out** to trigger RP-initiated logout and return to the home page.

## Configuration

All OIDC settings are in `appsettings.json` under the `"Oidc"` key:

| Key | Default | Description |
|---|---|---|
| `Authority` | `http://localhost:5001` | Issuer URL of the NetOidc provider |
| `ClientId` | `sample-client` | Client ID registered in the provider |
| `ClientSecret` | `sample-secret` | Client secret (used with `client_secret_basic`) |

> **Note:** `RequireHttpsMetadata` is `false` in this sample to allow plain HTTP in
> development. Remove that option (or set it to `true`) before deploying anywhere.
