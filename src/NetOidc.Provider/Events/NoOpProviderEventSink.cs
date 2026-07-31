using NetOidc.Provider.Abstractions.Events;

namespace NetOidc.Provider.Events;

/// <summary>No-op default event sink. Replace via <c>AddEventSink&lt;T&gt;()</c>.</summary>
internal sealed class NoOpProviderEventSink : IProviderEventSink
{
    public Task TokenIssuedAsync(TokenIssuedEvent e, CancellationToken ct = default) => Task.CompletedTask;
    public Task AuthorizationSucceededAsync(AuthorizationSucceededEvent e, CancellationToken ct = default) => Task.CompletedTask;
    public Task TokenIntrospectedAsync(TokenIntrospectedEvent e, CancellationToken ct = default) => Task.CompletedTask;
    public Task TokenRevokedAsync(TokenRevokedEvent e, CancellationToken ct = default) => Task.CompletedTask;
    public Task UserInfoRequestedAsync(UserInfoRequestedEvent e, CancellationToken ct = default) => Task.CompletedTask;
}
