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
}
