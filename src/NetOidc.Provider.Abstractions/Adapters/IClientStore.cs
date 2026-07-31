using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Abstractions.Adapters;

/// <summary>Lookup contract for registered OAuth2 clients.</summary>
public interface IClientStore
{
    Task<Client?> FindClientAsync(string clientId, CancellationToken ct = default);
}
