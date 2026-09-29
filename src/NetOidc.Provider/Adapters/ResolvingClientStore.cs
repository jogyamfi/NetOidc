using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Adapters;

/// <summary>A client resolved from an external source, and how long it may be cached.</summary>
public sealed record ResolvedClient(Client Client, TimeSpan CacheFor);

/// <summary>
/// Turns a URL <c>client_id</c> that is not registered into a client, e.g. from a Client ID
/// Metadata Document or an OpenID Federation trust chain. Return <c>null</c> when this source
/// does not apply or resolution fails.
/// </summary>
public interface IClientResolver
{
    Task<ResolvedClient?> ResolveAsync(string clientId, CancellationToken ct);
}

/// <summary>
/// Client store used by the endpoints: registered clients first; for an unknown https
/// <c>client_id</c>, the <see cref="IClientResolver"/>s in registration order. Resolved clients
/// are cached through <c>IAdapter&lt;Client&gt;</c>.
/// </summary>
public sealed class ResolvingClientStore : IClientStore
{
    /// <summary>Key prefix of resolved (and federation-registered) clients in <c>IAdapter&lt;Client&gt;</c>.</summary>
    public const string CachePrefix = "resolved-client:";

    private readonly IClientStore _inner;
    private readonly IEnumerable<IClientResolver> _resolvers;
    private readonly IAdapter<Client> _cache;

    public ResolvingClientStore(IClientStore inner, IEnumerable<IClientResolver> resolvers, IAdapter<Client> cache)
    {
        _inner = inner;
        _resolvers = resolvers;
        _cache = cache;
    }

    public async Task<Client?> FindClientAsync(string clientId, CancellationToken ct = default)
    {
        if (await _inner.FindClientAsync(clientId, ct) is { } registered)
            return registered;

        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return null;

        if (await _cache.FindAsync(CachePrefix + clientId, ct) is { } cached)
            return cached;

        foreach (var resolver in _resolvers)
        {
            if (await resolver.ResolveAsync(clientId, ct) is not { } resolved)
                continue;
            if (resolved.CacheFor > TimeSpan.Zero)
                await _cache.StoreAsync(CachePrefix + clientId, resolved.Client, resolved.CacheFor, ct);
            return resolved.Client;
        }
        return null;
    }
}
