using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Adapters;

/// <summary>Resolves clients from the static list in ProviderOptions.</summary>
public sealed class InMemoryClientStore : IClientStore
{
    private readonly IOptions<ProviderOptions> _options;

    public InMemoryClientStore(IOptions<ProviderOptions> options) => _options = options;

    public Task<Client?> FindClientAsync(string clientId, CancellationToken ct = default)
    {
        var client = _options.Value.StaticClients.FirstOrDefault(c => c.ClientId == clientId);
        return Task.FromResult(client);
    }
}
