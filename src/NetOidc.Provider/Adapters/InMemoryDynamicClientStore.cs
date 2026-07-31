using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Adapters;

/// <summary>
/// In-memory client store that serves both statically configured clients (from
/// <see cref="ProviderOptions.StaticClients"/>) and dynamically registered clients (DCR).
/// </summary>
public sealed class InMemoryDynamicClientStore : IDynamicClientStore
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly ConcurrentDictionary<string, Client> _dynamicClients = new();

    public InMemoryDynamicClientStore(IOptions<ProviderOptions> options) => _options = options;

    public Task<Client?> FindClientAsync(string clientId, CancellationToken ct = default)
    {
        var staticClient = _options.Value.StaticClients
            .FirstOrDefault(c => c.ClientId == clientId);
        if (staticClient is not null)
            return Task.FromResult<Client?>(staticClient);

        _dynamicClients.TryGetValue(clientId, out var dynamic);
        return Task.FromResult(dynamic);
    }

    public Task StoreClientAsync(Client client, CancellationToken ct = default)
    {
        _dynamicClients[client.ClientId] = client;
        return Task.CompletedTask;
    }

    public Task RemoveClientAsync(string clientId, CancellationToken ct = default)
    {
        _dynamicClients.TryRemove(clientId, out _);
        return Task.CompletedTask;
    }
}
