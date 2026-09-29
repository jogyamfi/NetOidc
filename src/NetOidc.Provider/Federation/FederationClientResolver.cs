using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Adapters;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Federation;

/// <summary>
/// OpenID Federation automatic registration (§12.1): an unknown <c>client_id</c> that is an
/// entity identifier is resolved through its trust chain; the client is cached until the chain
/// expires.
/// </summary>
public sealed class FederationClientResolver : IClientResolver
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly TrustChainResolver _chains;
    private readonly FederationClientFactory _factory;
    private readonly ILogger<FederationClientResolver> _logger;

    public FederationClientResolver(
        IOptions<ProviderOptions> options, TrustChainResolver chains, FederationClientFactory factory,
        ILogger<FederationClientResolver> logger)
    {
        _options = options;
        _chains = chains;
        _factory = factory;
        _logger = logger;
    }

    public async Task<ResolvedClient?> ResolveAsync(string clientId, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.FederationEnabled || !opts.FederationAutomaticRegistrationEnabled || opts.FederationTrustAnchors.Count == 0)
            return null;

        var (chain, _) = await _chains.ResolveAsync(clientId, "openid_relying_party", leafConfiguration: null, ct);
        if (chain is null)
            return null;

        var (client, error) = await _factory.CreateAsync(chain, automatic: true, ct);
        if (client is null)
        {
            _logger.LogInformation("Federation entity {EntityId} rejected for automatic registration: {Reason}", clientId, error);
            return null;
        }

        var cacheFor = chain.ExpiresAt - DateTimeOffset.UtcNow;
        return new ResolvedClient(client, cacheFor > TimeSpan.Zero ? cacheFor : TimeSpan.Zero);
    }
}
