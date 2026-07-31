---
name: dotnet-best-practices
description: ".NET 8 best practices for this codebase. Use when writing, reviewing, or refactoring C# code in NetOidc.Provider or NetOidc.Provider.Abstractions — including API design, nullability, async patterns, DI, security, testing, and performance."
---

# .NET Best Practices — NetOidc

## Project Context

- **Target framework:** `net8.0` (ASP.NET Core, `Microsoft.AspNetCore.App`)
- **Nullable reference types:** enabled (`<Nullable>enable</Nullable>`)
- **Implicit usings:** enabled
- **Libraries:** `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.IdentityModel.Tokens`, `System.Security.Cryptography`
- **No** OpenIddict / Duende — all protocol logic is implemented from scratch

---

## C# & Language

- Use `record` types for immutable value-like models (claims, error responses, metadata documents).
- Prefer `sealed` on classes that are not designed for inheritance.
- Use primary constructors (C# 12) for simple dependency injection in internal classes.
- Use `required` properties over constructor parameters when the type is consumed via object initializers.
- Prefer `is` pattern matching and `switch` expressions over chains of `if`/`else if`.
- Avoid `dynamic`; use generics or interfaces instead.
- Always use braces `{}` for `if`, `else`, `for`, `foreach`, `while`, and `using` blocks — even single-line bodies.
- Never suppress nullable warnings with `!` unless you have verified non-nullability at the call site and left a short comment explaining why.

---

## Async / Threading

- All I/O-bound methods must be `async Task` / `async Task<T>` and accept a `CancellationToken`.
- Pass `CancellationToken` through every call chain; never swallow it.
- Never use `.Result` or `.Wait()` — always `await`.
- Prefer `ValueTask<T>` for hot-path methods that frequently complete synchronously (e.g., cache lookups in adapters).
- Use `ConfigureAwait(false)` in library code (`NetOidc.Provider`, `NetOidc.Provider.Abstractions`); omit it in ASP.NET Core middleware/handlers where the synchronization context is irrelevant.

---

## Dependency Injection & Configuration

- Register services with the minimal required lifetime: prefer `Singleton` for stateless services, `Scoped` for per-request state (e.g., interaction sessions).
- Expose DI registration via extension methods on `IServiceCollection` (e.g., `AddNetOidc()`).
- Use `IOptions<T>` / `IOptionsMonitor<T>` for configuration; never inject raw `IConfiguration` into domain services.
- Validate options eagerly with `ValidateOnStart()` or `IValidateOptions<T>`.
- Avoid service locator pattern (`IServiceProvider` as a dependency).

---

## ASP.NET Core Middleware & Endpoints

- Register protocol endpoints as minimal API endpoints or `IEndpointRouteBuilder` extension methods; avoid legacy `IHttpHandler`-style patterns.
- Use `TypedResults` for typed, documented responses.
- Read the request body with `HttpContext.Request.ReadFormAsync(cancellationToken)` — never `ReadToEnd()` on the raw stream without a size limit.
- Apply `[RequestSizeLimit]` or `MaxRequestBodySize` for endpoints that accept untrusted input.
- Return `400 Bad Request` / `401 Unauthorized` / `403 Forbidden` via problem details (`IProblemDetailsService`) rather than throwing unhandled exceptions.

---

## Security

- **Never log secrets** (client secrets, tokens, private key material). Log token identifiers (JTI) only.
- Use `CryptographicOperations.FixedTimeEquals` for any constant-time comparison of secrets or MACs.
- Validate `redirect_uri` against the exact registered list before issuing any redirect.
- Do not build SQL/URLs by string concatenation from user input; use parameterized queries or typed builders.
- Tokens must be bound to their issuer and audience; always validate `iss`, `aud`, `exp`, `iat` claims before trusting a token.
- Use `RandomNumberGenerator.GetBytes()` for generating opaque tokens and state values; do not use `Random`.
- Sanitize error responses: never echo raw exception messages to OAuth clients; use `OAuth2Error` response objects.

---

## API Design (Public Surface — `NetOidc.Provider.Abstractions`)

- Keep the public API minimal; mark internal helpers `internal`.
- Use interfaces for all adapter contracts (`IAdapter<T>`); keep them in `NetOidc.Provider.Abstractions`.
- Design for source compatibility: avoid breaking changes to public interfaces; add new interface members via default interface methods or separate extension interfaces.
- Annotate public APIs with XML doc comments (`/// <summary>`).
- Use `[EditorBrowsable(EditorBrowsableState.Never)]` for infrastructure overloads not intended for end users.

---

## Error Handling

- Define domain errors as `record` types or `readonly struct` values rather than exceptions where possible; throw only for truly exceptional conditions.
- Use `Result<T>` or discriminated union patterns for expected failure paths (e.g., token validation outcomes).
- Catch only specific exception types; never swallow exceptions with empty `catch {}`.
- Log exceptions with structured context (`ILogger.LogError(ex, "...")`); include correlation IDs.

---

## Testing

- Use xUnit with `FluentAssertions` for all unit and integration tests.
- Structure tests as **Arrange / Act / Assert** with a blank line between each section.
- Prefer `Fake` implementations of adapters over mocking frameworks for adapter-level tests.
- Use `WebApplicationFactory<T>` for integration tests that exercise the ASP.NET Core pipeline.
- Test unhappy paths (expired tokens, missing parameters, mismatched redirect URIs) explicitly.
- Do not test internal implementation details; test observable behavior via public contracts.

---

## Performance

- Prefer `System.Text.Json` (STJ) over Newtonsoft.Json; configure a shared `JsonSerializerOptions` singleton.
- Use `ArrayPool<byte>` / `MemoryPool<byte>` for short-lived byte buffers in JOSE operations.
- Cache JWKS key sets and discovery documents aggressively (they change infrequently).
- Avoid `LINQ` in hot paths (token validation, claim assembly); prefer direct iteration.

---

## References

- [.NET 8 Breaking Changes](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-8/breaking-changes)
- [ASP.NET Core Security Docs](https://learn.microsoft.com/en-us/aspnet/core/security/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519)
