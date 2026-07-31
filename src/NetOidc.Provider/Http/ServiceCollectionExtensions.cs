using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Adapters;
using NetOidc.Provider.Authorization;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Discovery;
using NetOidc.Provider.Interaction;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Token;
using NetOidc.Provider.UserInfo;

namespace NetOidc.Provider.Http;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the OIDC provider core services and returns a builder for
    /// further configuration.
    /// </summary>
    public static NetOidcBuilder AddNetOidc(
        this IServiceCollection services,
        Action<ProviderOptions> configure)
    {
        services.Configure(configure);

        // Storage adapters — in-memory defaults; callers can override with TryAdd.
        services.TryAddSingleton<IAdapter<Grant>, InMemoryAdapter<Grant>>();
        services.TryAddSingleton<IAdapter<AccessToken>, InMemoryAdapter<AccessToken>>();
        services.TryAddSingleton<IAdapter<AuthorizationCode>, InMemoryAdapter<AuthorizationCode>>();
        services.TryAddSingleton<IAdapter<RefreshToken>, InMemoryAdapter<RefreshToken>>();
        services.TryAddSingleton<IClientStore, InMemoryClientStore>();

        // JOSE
        services.TryAddSingleton<SigningKeyProvider>();
        services.TryAddSingleton<TokenFactory>();

        // Discovery
        services.TryAddSingleton<DiscoveryService>();

        // Interaction
        services.TryAddSingleton<IInteractionService, DefaultInteractionService>();

        // Claims
        services.TryAddSingleton<SubjectIdentifierService>();

        // Endpoint handlers
        services.TryAddSingleton<AuthorizationEndpointHandler>();
        services.TryAddSingleton<TokenEndpointHandler>();
        services.TryAddSingleton<UserInfoEndpointHandler>();
        services.TryAddSingleton<IntrospectionEndpointHandler>();
        services.TryAddSingleton<RevocationEndpointHandler>();

        return new NetOidcBuilder(services);
    }
}
