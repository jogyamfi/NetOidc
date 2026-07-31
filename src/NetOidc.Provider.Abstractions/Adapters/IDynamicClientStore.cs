using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Abstractions.Adapters;

/// <summary>
/// Extends <see cref="IClientStore"/> with write operations needed for
/// Dynamic Client Registration (RFC 7591/7592).
/// </summary>
public interface IDynamicClientStore : IClientStore
{
    Task StoreClientAsync(Client client, CancellationToken ct = default);

    Task RemoveClientAsync(string clientId, CancellationToken ct = default);
}
