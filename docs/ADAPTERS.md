# Storage adapters

NetOidc keeps all of its state (codes, tokens, grants, sessions, consent, pending requests)
behind small storage interfaces. The defaults are in-memory: fine for development and a single
instance, lost on restart. A production deployment with more than one instance, or one that
must survive restarts, replaces them with a shared store such as Redis or a SQL database.

This guide covers what to implement, the guarantees each method must give, and how to
register your implementations.

## The interfaces

All of them live in `NetOidc.Provider.Abstractions`, so an adapter package does not need to
reference the provider itself.

| Interface | Purpose |
|-----------|---------|
| `IAdapter<T>` | Key/value store for one model type, with optional expiry and atomic one-time consumption |
| `IReplayCache` | Records one-time identifiers (`jti` values) and reports replays |
| `IClientStore` | Looks up registered clients |
| `IDynamicClientStore` | `IClientStore` plus writes, for Dynamic Client Registration |

### `IAdapter<T>`

```csharp
public interface IAdapter<T> where T : class
{
    Task<T?> FindAsync(string id, CancellationToken ct = default);
    Task StoreAsync(string id, T entity, TimeSpan? expiresIn = null, CancellationToken ct = default);
    Task RemoveAsync(string id, CancellationToken ct = default);
    Task<T?> ConsumeAsync(string id, CancellationToken ct = default);
}
```

| Method | Contract |
|--------|----------|
| `FindAsync` | Returns the entity, or `null` when it is absent **or has expired**. Never return an expired record, even if your store has not deleted it yet. |
| `StoreAsync` | Inserts or **overwrites** the entity. `expiresIn = null` means no expiry. The provider relies on overwrite: for example, a spent authorization code is replaced by a tombstone under the same id. |
| `RemoveAsync` | Deletes the entity. Removing a missing id is not an error. |
| `ConsumeAsync` | Returns the entity and deletes it **in one atomic step**. See below. |

### The atomicity contract

`ConsumeAsync` is how the provider enforces single use. For concurrent calls with the same
`id`, **at most one caller may receive the entity**; every other caller must get `null`.
A find-then-remove sequence is not enough: two requests that race between the find and the
remove would both succeed, which lets an attacker redeem an authorization code or refresh
token twice.

| Store | Atomic consumption |
|-------|--------------------|
| Redis | `GETDEL key` (Redis 6.2+), or a Lua script doing `GET` + `DEL` |
| PostgreSQL | `DELETE FROM store WHERE id = @id AND (expires_at IS NULL OR expires_at > now()) RETURNING payload` |
| SQL Server | `DELETE FROM store OUTPUT DELETED.payload WHERE id = @id AND (expires_at IS NULL OR expires_at > SYSUTCDATETIME())` |
| MongoDB | `findOneAndDelete({ _id: id, ... })` |
| Cosmos DB / DynamoDB | Conditional delete returning the old item (`ReturnValues = ALL_OLD`) |

These records are consumed, so their adapters must honour the contract:

| Model | Consumed when |
|-------|---------------|
| `AuthorizationCode` | the code is redeemed at the token endpoint |
| `RefreshToken` | a rotating refresh token is redeemed |
| `PushedAuthorizationRequest` | the `request_uri` is used at the authorization endpoint |
| `DeviceCode` | an approved device code is redeemed |
| `BackchannelAuthenticationRequest` | a completed CIBA request is redeemed |
| `PreAuthorizedCode` | an OID4VCI pre-authorized code is redeemed |
| `CredentialNonce` | an OID4VCI `c_nonce` is used in a proof |
| `DeferredCredentialTransaction` | a deferred credential is collected |

The provider's own tests check this end to end: 50 concurrent redemptions of each artifact
must produce exactly one success (`ConcurrencyTests`). Run the same checks against your
adapter before you deploy it (see [Testing an adapter](#testing-an-adapter)).

### `IReplayCache`

```csharp
public interface IReplayCache
{
    Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default);
}
```

`TryAddAsync` must **atomically** insert `key` if it is not already present (or has expired)
and return `true`; otherwise it returns `false`. The provider records DPoP proof `jti`s,
client-assertion `jti`s, JWT-bearer grant `jti`s and signed CIBA request `jti`s here.

| Store | Atomic insert |
|-------|---------------|
| Redis | `SET key 1 NX PXAT <expiresAt ms>` and check for `OK` |
| SQL | `INSERT` with a primary key on `key`; a unique-key violation means replay. Delete expired rows first, or treat an expired row as absent in an `UPSERT ... WHERE expires_at < now()` |

### Client stores

`IClientStore.FindClientAsync` returns a `Client` or `null`. The provider wraps your store to
add static clients (`ProviderOptions.StaticClients`), federation clients and Client ID Metadata
Document clients, so your store only needs the clients you manage.

Dynamic Client Registration writes through `IDynamicClientStore` (`StoreClientAsync`,
`RemoveClientAsync`). Registrations are stored with the SHA-256 hash of their registration
access token (`Client.RegistrationAccessTokenHash`), never the token itself.

## Registering adapters

The provider registers a default for each closed type (`IAdapter<RefreshToken>`,
`IAdapter<Grant>`, ...) with `TryAdd`. Register yours **per model type** before calling
`AddNetOidc`. An open-generic registration (`typeof(IAdapter<>)`) is not enough: the
provider's closed defaults would still be added, and a closed registration wins.

```csharp
Type[] models =
[
    typeof(AuthorizationCode), typeof(AccessToken), typeof(RefreshToken), typeof(Grant),
    typeof(Session), typeof(Consent), typeof(PendingInteraction), typeof(PushedAuthorizationRequest),
    typeof(DeviceCode), typeof(BackchannelAuthenticationRequest), typeof(Client),
    typeof(CredentialNonce), typeof(PreAuthorizedCode), typeof(StoredCredentialOffer),
    typeof(DeferredCredentialTransaction), typeof(CredentialNotificationRecord),
];
foreach (var model in models)
    builder.Services.AddSingleton(
        typeof(IAdapter<>).MakeGenericType(model), typeof(RedisAdapter<>).MakeGenericType(model));

builder.Services.AddSingleton<IReplayCache, RedisReplayCache>();
builder.Services.AddSingleton<IDynamicClientStore, SqlClientStore>();

builder.Services.AddNetOidc(options => { /* ... */ });
```

`IAdapter<Client>` caches clients resolved from federation trust chains and Client ID
Metadata Documents; `IDynamicClientStore` holds dynamically registered clients.

## Models and lifetimes

| Model | Lifetime (default option) |
|-------|----------------------------|
| `AuthorizationCode` | `AuthorizationCodeLifetimeSeconds`; spent codes stay as tombstones for `AccessTokenLifetimeSeconds` so a late replay still revokes what was issued |
| `AccessToken` | `AccessTokenLifetimeSeconds` |
| `RefreshToken` | `RefreshTokenLifetimeSeconds`; rotated tokens stay as tombstones for reuse detection |
| `Grant` | as long as any token issued under it. **Removing a grant revokes every token issued from it**, so do not evict grants early |
| `OidcSession` | `SessionLifetimeSeconds` |
| `Consent` | until revoked, or the lifetime passed to `ConsentService.GrantAsync` |
| `PendingInteraction` | `InteractionLifetimeSeconds` |
| `PushedAuthorizationRequest` | `PushedAuthorizationLifetimeSeconds` |
| `DeviceCode`, `BackchannelAuthenticationRequest` | `DeviceCodeLifetimeSeconds`, `CibaAuthReqIdLifetimeSeconds` |
| OID4VCI records | the `Vci*LifetimeSeconds` options |

Always pass `expiresIn` through to the store's native TTL where it has one. The provider
expects expired records to disappear by themselves; nothing else cleans them up.

## Security notes

- **Ids are secrets.** For authorization codes, refresh tokens, PAR `request_uri`s, device
  codes and pre-authorized codes, the id is the bearer value itself. Consider storing
  `SHA-256(id)` as the key so a read-only leak of the store does not yield usable tokens. This
  is transparent to the provider as long as every method hashes the same way.
- **Serialization.** Models are plain classes with `init` properties; `System.Text.Json`
  round-trips them. Keep the payload opaque to the store, and encrypt it at rest if your store
  is shared with other applications: records contain subjects, scopes and claims requests.
- **Clock.** Expiry is compared with the provider's UTC clock. Keep instance clocks in sync
  (NTP); DPoP, client assertions and request objects also allow only small clock skew.
- **Multiple instances** also need a shared `DPoPNonceSecret` when DPoP nonces are enabled,
  shared keys (see [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)) and a shared ASP.NET Core Data
  Protection key ring (antiforgery and authentication cookies).

## Testing an adapter

At minimum, check that your adapter:

1. never returns a record after its `expiresIn` has passed;
2. overwrites on `StoreAsync` with an existing id;
3. returns the record from exactly one of 50 concurrent `ConsumeAsync` calls;
4. returns `true` from exactly one of 50 concurrent `IReplayCache.TryAddAsync` calls for the same key.

`test/NetOidc.Provider.Tests/InMemoryAdapterTests.cs` shows the concurrency check for the
in-memory adapter; the same test can be pointed at yours.
