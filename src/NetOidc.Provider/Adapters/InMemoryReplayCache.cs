using System.Collections.Concurrent;
using NetOidc.Provider.Abstractions.Adapters;

namespace NetOidc.Provider.Adapters;

/// <summary>Process-local <see cref="IReplayCache"/>; entries are pruned lazily on insert.</summary>
public sealed class InMemoryReplayCache : IReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new();

    public Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;

        // An expired entry for the same key may be replaced.
        if (_entries.TryGetValue(key, out var existing) && existing <= now)
            _entries.TryRemove(new KeyValuePair<string, DateTimeOffset>(key, existing));

        var added = _entries.TryAdd(key, expiresAt);
        Prune(now);
        return Task.FromResult(added);
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var kv in _entries)
            if (kv.Value <= now)
                _entries.TryRemove(kv);
    }
}
