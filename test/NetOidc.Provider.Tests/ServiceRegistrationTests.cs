using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Tests;

public sealed class ServiceRegistrationTests
{
    private static ServiceProvider BuildProvider(Action<ProviderOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddNetOidc(opts =>
        {
            opts.Issuer = "https://example.com";
            configure?.Invoke(opts);
        });
        return services.BuildServiceProvider();
    }

    [Fact]
    public void AddNetOidc_RegistersProviderOptions()
    {
        using var sp = BuildProvider();
        var options = sp.GetRequiredService<IOptions<ProviderOptions>>();
        Assert.Equal("https://example.com", options.Value.Issuer);
    }

    [Fact]
    public void AddNetOidc_RegistersGrantAdapter()
    {
        using var sp = BuildProvider();
        Assert.NotNull(sp.GetService<IAdapter<Grant>>());
    }

    [Fact]
    public void AddNetOidc_RegistersAccessTokenAdapter()
    {
        using var sp = BuildProvider();
        Assert.NotNull(sp.GetService<IAdapter<AccessToken>>());
    }

    [Fact]
    public void AddNetOidc_RegistersClientStore()
    {
        using var sp = BuildProvider();
        Assert.NotNull(sp.GetService<IClientStore>());
    }

    [Fact]
    public async Task ClientStore_FindsStaticClient()
    {
        using var sp = BuildProvider(opts =>
        {
            opts.StaticClients =
            [
                new Client
                {
                    ClientId = "test-client",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    RedirectUris = ["https://app.example.com/cb"],
                }
            ];
        });

        var store = sp.GetRequiredService<IClientStore>();
        var client = await store.FindClientAsync("test-client");

        Assert.NotNull(client);
        Assert.Equal("test-client", client.ClientId);
    }

    [Fact]
    public async Task ClientStore_ReturnsNull_ForUnknownClient()
    {
        using var sp = BuildProvider();
        var store = sp.GetRequiredService<IClientStore>();
        Assert.Null(await store.FindClientAsync("unknown"));
    }
}
