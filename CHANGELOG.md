# Changelog

All notable changes to NetOidc are documented here. The project is pre-1.0: breaking
changes are allowed between minor versions and are listed explicitly.

## [Unreleased]

Security remediation, Phase 1 (see [docs/REMEDIATION_PLAN.md](docs/REMEDIATION_PLAN.md)).

### Security

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

### Added

- `IReplayCache` (with `InMemoryReplayCache`), `RefreshTokenService`.
- `ProviderOptions`: `AuthorizeTokenExchange`, `AuthorizeJwtBearerSubject`, `AuthorizeIntrospection`,
  `DcrAllowedGrantTypes`, `DcrAllowPrivateNetworkUris`.
- `Client.SectorIdentifierUri`; `RefreshToken.GrantId`, `ConsumedAt`, `CnfJwkThumbprint`, `CnfX5tS256`.
- Introspection responses include `cnf`, `aud`, the real `iat`, and `token_type: DPoP` for bound tokens.
