namespace NetOidc.Provider.Abstractions.Events;

/// <summary>
/// Receives lifecycle events emitted by the provider.
/// Register a custom implementation via <c>AddNetOidc(...).AddEventSink&lt;T&gt;()</c>.
/// </summary>
public interface IProviderEventSink
{
    /// <summary>Called after a token grant succeeds (authorization_code, client_credentials, refresh_token, etc.).</summary>
    Task TokenIssuedAsync(TokenIssuedEvent e, CancellationToken ct = default);

    /// <summary>Called after the authorization endpoint issues a code or token to an authenticated user.</summary>
    Task AuthorizationSucceededAsync(AuthorizationSucceededEvent e, CancellationToken ct = default);

    /// <summary>Called after an introspection request is processed.</summary>
    Task TokenIntrospectedAsync(TokenIntrospectedEvent e, CancellationToken ct = default);

    /// <summary>Called after a token is revoked.</summary>
    Task TokenRevokedAsync(TokenRevokedEvent e, CancellationToken ct = default);

    /// <summary>Called after the UserInfo endpoint successfully serves claims.</summary>
    Task UserInfoRequestedAsync(UserInfoRequestedEvent e, CancellationToken ct = default);

    // ── Failure and lifecycle events (default: ignored) ───────────────────────

    /// <summary>Called when a client fails to authenticate at any endpoint.</summary>
    Task ClientAuthenticationFailedAsync(ClientAuthenticationFailedEvent e, CancellationToken ct = default) =>
        Task.CompletedTask;

    /// <summary>Called when the token endpoint rejects a request.</summary>
    Task TokenRequestFailedAsync(TokenRequestFailedEvent e, CancellationToken ct = default) =>
        Task.CompletedTask;

    /// <summary>Called when the authorization endpoint returns an error.</summary>
    Task AuthorizationFailedAsync(AuthorizationFailedEvent e, CancellationToken ct = default) =>
        Task.CompletedTask;

    /// <summary>Called after an End-User session ends through the end-session endpoint.</summary>
    Task LoggedOutAsync(LoggedOutEvent e, CancellationToken ct = default) => Task.CompletedTask;

    /// <summary>Called when an End-User approves or denies a device or CIBA request.</summary>
    Task AuthorizationDecisionAsync(AuthorizationDecisionEvent e, CancellationToken ct = default) =>
        Task.CompletedTask;

    /// <summary>Called when a client is registered, updated or deleted through DCR.</summary>
    Task ClientRegistrationChangedAsync(ClientRegistrationChangedEvent e, CancellationToken ct = default) =>
        Task.CompletedTask;
}
