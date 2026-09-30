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
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<ProviderOptions>, FapiProfileValidator>());

        // Security-relevant option validation (pairwise salt, ...); fails at startup.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<ProviderOptions>, ProviderOptionsValidator>());
        services.AddOptions<ProviderOptions>().ValidateOnStart();

        // Storage adapters — in-memory defaults; callers can override with TryAdd.
        services.TryAddSingleton<IAdapter<Grant>, InMemoryAdapter<Grant>>();
        services.TryAddSingleton<IAdapter<AccessToken>, InMemoryAdapter<AccessToken>>();
        services.TryAddSingleton<IAdapter<AuthorizationCode>, InMemoryAdapter<AuthorizationCode>>();
        services.TryAddSingleton<IAdapter<RefreshToken>, InMemoryAdapter<RefreshToken>>();
        services.TryAddSingleton<IAdapter<OidcSession>, InMemoryAdapter<OidcSession>>();
        services.TryAddSingleton<IAdapter<PushedAuthorizationRequest>, InMemoryAdapter<PushedAuthorizationRequest>>();
        services.TryAddSingleton<IAdapter<Consent>, InMemoryAdapter<Consent>>();
        services.TryAddSingleton<IAdapter<PendingInteraction>, InMemoryAdapter<PendingInteraction>>();
        services.TryAddSingleton<IAdapter<CredentialNonce>, InMemoryAdapter<CredentialNonce>>();
        services.TryAddSingleton<IAdapter<PreAuthorizedCode>, InMemoryAdapter<PreAuthorizedCode>>();
        services.TryAddSingleton<IAdapter<StoredCredentialOffer>, InMemoryAdapter<StoredCredentialOffer>>();
        services.TryAddSingleton<IAdapter<DeferredCredentialTransaction>, InMemoryAdapter<DeferredCredentialTransaction>>();
        services.TryAddSingleton<IAdapter<CredentialNotificationRecord>, InMemoryAdapter<CredentialNotificationRecord>>();

        // Phase 6 storage adapters
        services.TryAddSingleton<IAdapter<DeviceCode>, InMemoryAdapter<DeviceCode>>();
        services.TryAddSingleton<IAdapter<BackchannelAuthenticationRequest>, InMemoryAdapter<BackchannelAuthenticationRequest>>();

        // Replay detection for one-time JWT identifiers (jti) and nonces.
        services.TryAddSingleton<IReplayCache, InMemoryReplayCache>();

        // Client store: InMemoryDynamicClientStore satisfies both IClientStore and IDynamicClientStore.
        services.TryAddSingleton<InMemoryDynamicClientStore>();
        // Endpoints resolve clients through ResolvingClientStore: registered clients first, then
        // URL client_ids via the IClientResolvers (federation, Client ID Metadata Documents).
        services.TryAddSingleton<IClientStore>(sp => new ResolvingClientStore(
            sp.GetRequiredService<InMemoryDynamicClientStore>(),
            sp.GetServices<IClientResolver>(),
            sp.GetRequiredService<IAdapter<Client>>()));
        services.TryAddSingleton<IAdapter<Client>, InMemoryAdapter<Client>>();
        services.TryAddSingleton<SafeHttpFetcher>();
        services.TryAddSingleton<Jose.ClientJwksProvider>();
        services.TryAddSingleton<Token.ClientAttestationValidator>();
        // Resolver order matters: a federation entity is tried before a metadata document.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClientResolver, FederationClientResolver>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClientResolver, ClientIdMetadataDocumentResolver>());
        services.TryAddSingleton<IDynamicClientStore>(sp => sp.GetRequiredService<InMemoryDynamicClientStore>());

        // JOSE
        // Keys: configured (or, in development, generated) via IKeyStore; startup check refuses
        // generated keys in Production.
        services.TryAddSingleton<IKeyStore, ConfiguredKeyStore>();
        services.TryAddSingleton<KeyRing>();
        services.AddHostedService<KeyRingStartupCheck>();
        services.TryAddSingleton<TokenFactory>();
        services.TryAddSingleton<RequestObjectValidator>();

        // Phase 5 — DPoP
        services.TryAddSingleton<DPopProofValidator>();
        services.TryAddSingleton<DPoPNonceService>();

        // Discovery
        services.TryAddSingleton<DiscoveryService>();

        // Interaction
        services.TryAddSingleton<ConsentService>();
        services.TryAddSingleton<InteractionDenialService>();
        services.TryAddSingleton<IInteractionService, DefaultInteractionService>();

        // Claims
        services.TryAddSingleton<SubjectIdentifierService>();

        // Session
        services.TryAddSingleton<SessionService>();

        // Back-channel logout (requires IHttpClientFactory)
        // Logout notifications: no redirects, short timeout. Dynamically registered clients
        // use a connector that refuses private/loopback destinations (SSRF protection).
        services.AddHttpClient(BackChannelLogoutService.TrustedHttpClientName, c => c.Timeout = TimeSpan.FromSeconds(5))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
        services.AddHttpClient(BackChannelLogoutService.UntrustedHttpClientName, c => c.Timeout = TimeSpan.FromSeconds(5))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                // A proxy would resolve and connect on our behalf, bypassing the address check.
                UseProxy = false,
                ConnectCallback = NetworkAddressPolicy.ConnectPublicOnlyAsync,
            });
        services.TryAddSingleton<BackChannelLogoutService>();

        // Grants, refresh-token rotation and the shared token issuer
        services.TryAddSingleton<GrantService>();
        services.TryAddSingleton<RefreshTokenService>();
        services.TryAddSingleton<UserClaimsService>();
        services.TryAddSingleton<TokenIssuanceService>();

        // Client authentication (all token-endpoint auth methods, mTLS certificate sourcing)
        services.TryAddSingleton<ClientAuthenticator>();

        // Access-token liveness (signature, store record, grant) shared by all resource endpoints
        services.TryAddSingleton<AccessTokenService>();

        // Abuse protection: antiforgery for user-facing POSTs, in-handler throttles
        services.AddAntiforgery();
        services.TryAddSingleton<RequestThrottle>();

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
        services.TryAddSingleton<ICibaService, CibaService>();

        // Phase 8 — Federation
        services.TryAddSingleton<FederationService>();
        services.TryAddSingleton<FederationEndpointHandler>();
        services.TryAddSingleton<TrustChainResolver>();
        services.TryAddSingleton<FederationClientFactory>();
        services.TryAddSingleton<FederationRegistrationEndpointHandler>();

        // Phase 8 — VCI
        services.TryAddSingleton<VciService>();
        services.TryAddSingleton<VciEndpointHandler>();
        services.TryAddSingleton<CredentialOfferService>();

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

        // Never "*": allow the configured origins plus the origins of registered redirect URIs.
        var origins = opts.CorsAllowedOrigins
            .Concat(opts.StaticClients.SelectMany(c => c.RedirectUris))
            .Select(OriginOf)
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        options.AddPolicy("NetOidcCors", policy => policy
            .WithOrigins(origins)
            .WithMethods("GET", "POST")
            .WithHeaders("Authorization", "Content-Type", "DPoP")
            .WithExposedHeaders("WWW-Authenticate", "DPoP-Nonce"));
    }

    /// <summary>Returns the web origin (scheme://host[:port]) of an http(s) URI, else <c>null</c>.</summary>
    private static string? OriginOf(string uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u) && u.Scheme is "https" or "http"
            ? u.GetLeftPart(UriPartial.Authority)
            : null;
}
