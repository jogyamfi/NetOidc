using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace NetOidc.Provider.Configuration;

/// <summary>
/// Fluent builder returned by AddNetOidc(). Future phases attach
/// extension methods (e.g. AddInMemoryClients, UseEfCoreAdapters).
/// </summary>
public sealed class NetOidcBuilder
{
    public IServiceCollection Services { get; }

    internal NetOidcBuilder(IServiceCollection services) => Services = services;

    /// <summary>
    /// Applies the specified FAPI compliance profile. When <paramref name="validate"/>
    /// is <c>true</c>, the provider validates the full <see cref="ProviderOptions"/>
    /// graph against the profile constraints at startup (via
    /// <see cref="IValidateOptions{TOptions}"/>).
    /// </summary>
    public NetOidcBuilder UseFapiProfile(FapiProfile profile, bool validate = false)
    {
        Services.PostConfigure<ProviderOptions>(opts =>
        {
            opts.FapiProfile = profile;
            opts.FapiProfileValidationEnabled = validate;
        });
        return this;
    }
}
