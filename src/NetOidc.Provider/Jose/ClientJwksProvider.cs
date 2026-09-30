using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Jose;

/// <summary>
/// The current key set of a client. For clients with a <c>jwks_uri</c>, a signature that does
/// not verify triggers a re-fetch (OIDC Core §10.1.1: the RP rotates keys by publishing new ones
/// there), at most once per <see cref="MinRefreshInterval"/> per client. The refreshed set is kept
/// in memory per instance; the registered <see cref="Client.JwksJson"/> is the fallback.
/// </summary>
internal sealed class ClientJwksProvider
{
    public static readonly TimeSpan MinRefreshInterval = TimeSpan.FromSeconds(30);
    private const int MaxJwksBytes = 64 * 1024;

    private readonly SafeHttpFetcher _fetcher;
    private readonly IOptions<ProviderOptions> _options;
    private readonly ConcurrentDictionary<string, (string? Jwks, DateTimeOffset FetchedAt)> _fetched = new(StringComparer.Ordinal);

    public ClientJwksProvider(SafeHttpFetcher fetcher, IOptions<ProviderOptions> options)
    {
        _fetcher = fetcher;
        _options = options;
    }

    /// <summary>The client's key set: the latest fetched copy of its <c>jwks_uri</c>, else its registered JWKS.</summary>
    public string? Current(Client client) =>
        client.JwksUri is not null && _fetched.TryGetValue(Key(client), out var entry) && entry.Jwks is not null
            ? entry.Jwks
            : client.JwksJson;

    /// <summary>
    /// Re-fetches the client's <c>jwks_uri</c>. Returns the new key set when it differs from
    /// <see cref="Current"/>; <c>null</c> when the client has no <c>jwks_uri</c>, was refreshed
    /// recently, the fetch failed, or nothing changed.
    /// </summary>
    public async Task<string?> RefreshAsync(Client client, CancellationToken ct)
    {
        if (client.JwksUri is null) return null;
        var key = Key(client);
        var now = DateTimeOffset.UtcNow;
        if (_fetched.TryGetValue(key, out var last) && now - last.FetchedAt < MinRefreshInterval)
            return null;

        var previous = Current(client);
        // Record the attempt first, so failures are throttled as well.
        _fetched[key] = (last.Jwks, now);

        var document = await _fetcher.GetAsync(client.JwksUri, MaxJwksBytes, "application/json", ct,
            _options.Value.DcrAllowPrivateNetworkUris);
        if (document is null || !IsPublicKeySet(document.Content))
            return null;

        _fetched[key] = (document.Content, now);
        return document.Content == previous ? null : document.Content;
    }

    // A re-registration may change the jwks_uri; key the cache on both.
    private static string Key(Client client) => client.ClientId + " " + client.JwksUri;

    private static bool IsPublicKeySet(string json)
    {
        try
        {
            var set = new JsonWebKeySet(json);
            return set.Keys.Count > 0 && set.Keys.All(k => !k.HasPrivateKey && string.IsNullOrEmpty(k.K));
        }
        catch (Exception ex) when (ex is ArgumentException or System.Text.Json.JsonException)
        {
            return false;
        }
    }
}
