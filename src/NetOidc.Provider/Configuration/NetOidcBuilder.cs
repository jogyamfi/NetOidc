using Microsoft.Extensions.DependencyInjection;

namespace NetOidc.Provider.Configuration;

/// <summary>
/// Fluent builder returned by AddNetOidc(). Future phases attach
/// extension methods (e.g. AddInMemoryClients, UseEfCoreAdapters).
/// </summary>
public sealed class NetOidcBuilder
{
    public IServiceCollection Services { get; }

    internal NetOidcBuilder(IServiceCollection services) => Services = services;
}
