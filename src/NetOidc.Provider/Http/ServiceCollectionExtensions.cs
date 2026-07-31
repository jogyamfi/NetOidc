using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Adapters;
using NetOidc.Provider.Events;
using NetOidc.Provider.Authorization;
using NetOidc.Provider.Ciba;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Dcr;
using NetOidc.Provider.Device;
using NetOidc.Provider.Discovery;
using NetOidc.Provider.DPoP;
using NetOidc.Provider.Federation;
using NetOidc.Provider.Interaction;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Logout;
using NetOidc.Provider.Par;
using NetOidc.Provider.Session;
using NetOidc.Provider.Token;
using NetOidc.Provider.UserInfo;
using NetOidc.Provider.Vci;
using OidcSession = NetOidc.Provider.Abstractions.Models.Session;

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

        // Phase 9: event sink — default is no-op; callers can replace via AddEventSink<T>().
        services.TryAddSingleton<IProviderEventSink, NoOpProviderEventSink>();

        // Phase 7: FAPI profile validation (runs on first options access / startup).
        services.TryAddSingleton<IValidateOptions<ProviderOptions>, FapiProfileValidator>();

        // Storage adapters — in-memory defaults; callers can override with TryAdd.
        services.TryAddSingleton<IAdapter<Grant>, InMemoryAdapter<Grant>>();
        services.TryAddSingleton<IAdapter<AccessToken>, InMemoryAdapter<AccessToken>>();
        services.TryAddSingleton<IAdapter<AuthorizationCode>, InMemoryAdapter<AuthorizationCode>>();
        services.TryAddSingleton<IAdapter<RefreshToken>, InMemoryAdapter<RefreshToken>>();
        services.TryAddSingleton<IAdapter<OidcSession>, InMemoryAdapter<OidcSession>>();
        services.TryAddSingleton<IAdapter<PushedAuthorizationRequest>, InMemoryAdapter<PushedAuthorizationRequest>>();

        // Phase 6 storage adapters
        services.TryAddSingleton<IAdapter<DeviceCode>, InMemoryAdapter<DeviceCode>>();
        services.TryAddSingleton<IAdapter<BackchannelAuthenticationRequest>, InMemoryAdapter<BackchannelAuthenticationRequest>>();

        // Client store: InMemoryDynamicClientStore satisfies both IClientStore and IDynamicClientStore.
        services.TryAddSingleton<InMemoryDynamicClientStore>();
        services.TryAddSingleton<IClientStore>(sp => sp.GetRequiredService<InMemoryDynamicClientStore>());
        services.TryAddSingleton<IDynamicClientStore>(sp => sp.GetRequiredService<InMemoryDynamicClientStore>());

        // JOSE
        services.TryAddSingleton<SigningKeyProvider>();
        services.TryAddSingleton<EncryptionKeyProvider>();
        services.TryAddSingleton<TokenFactory>();
        services.TryAddSingleton<RequestObjectValidator>();

        // Phase 5 — DPoP
        services.TryAddSingleton<DPopProofValidator>();

        // Discovery
        services.TryAddSingleton<DiscoveryService>();

        // Interaction
        services.TryAddSingleton<IInteractionService, DefaultInteractionService>();

        // Claims
        services.TryAddSingleton<SubjectIdentifierService>();

        // Session
        services.TryAddSingleton<SessionService>();

        // Back-channel logout (requires IHttpClientFactory)
        services.AddHttpClient();
        services.TryAddSingleton<BackChannelLogoutService>();

        // Endpoint handlers
        services.TryAddSingleton<AuthorizationEndpointHandler>();
        services.TryAddSingleton<TokenEndpointHandler>();
        services.TryAddSingleton<UserInfoEndpointHandler>();
        services.TryAddSingleton<IntrospectionEndpointHandler>();
        services.TryAddSingleton<RevocationEndpointHandler>();
        services.TryAddSingleton<DynamicRegistrationEndpointHandler>();
        services.TryAddSingleton<LogoutEndpointHandler>();
        services.TryAddSingleton<ParEndpointHandler>();

        // Phase 6 endpoint handlers
        services.TryAddSingleton<DeviceAuthorizationEndpointHandler>();
        services.TryAddSingleton<DeviceVerificationEndpointHandler>();
        services.TryAddSingleton<CibaEndpointHandler>();

        // Phase 8 — Federation
        services.TryAddSingleton<FederationService>();
        services.TryAddSingleton<FederationEndpointHandler>();

        // Phase 8 — VCI
        services.TryAddSingleton<VciService>();
        services.TryAddSingleton<VciEndpointHandler>();

        // Phase 8 — Client ID Metadata Document
        services.TryAddSingleton<ClientIdMetadataEndpointHandler>();

        // Phase 8 — CORS
        services.AddCors();
        services.AddSingleton<Microsoft.Extensions.Options.IConfigureOptions<
            Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>, NetOidcCorsSetup>();

        return new NetOidcBuilder(services);
    }
}

/// <summary>
/// Registers the "NetOidcCors" CORS policy from <see cref="ProviderOptions"/> at startup.
/// Callers must add <c>app.UseCors()</c> to activate the middleware.
/// </summary>
internal sealed class NetOidcCorsSetup
    : Microsoft.Extensions.Options.IConfigureOptions<Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>
{
    private readonly IOptions<ProviderOptions> _providerOptions;

    public NetOidcCorsSetup(IOptions<ProviderOptions> providerOptions)
        => _providerOptions = providerOptions;

    public void Configure(Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions options)
    {
        var opts = _providerOptions.Value;
        if (!opts.CorsEnabled)
            return;

        options.AddPolicy("NetOidcCors", policy =>
        {
            if (opts.CorsAllowedOrigins.Count == 0)
                policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
            else
                policy.WithOrigins([.. opts.CorsAllowedOrigins])
                      .AllowAnyMethod()
                      .AllowAnyHeader();
        });
    }
}
