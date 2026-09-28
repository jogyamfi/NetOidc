using System.Collections.Concurrent;
using NetOidc.Provider.Abstractions.Adapters;

namespace NetOidc.Provider.Adapters;

/// <summary>Process-local <see cref="IReplayCache"/>; expired entries are swept periodically.</summary>
public sealed class InMemoryReplayCache : IReplayCache
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new();
    private long _nextSweepTicks = DateTimeOffset.UtcNow.Add(SweepInterval).UtcTicks;

    /// <summary>Number of entries currently held.</summary>
    internal int Count => _entries.Count;

    public Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;

        // An expired entry for the same key may be replaced.
        if (_entries.TryGetValue(key, out var existing) && existing <= now)
            _entries.TryRemove(new KeyValuePair<string, DateTimeOffset>(key, existing));

        var added = _entries.TryAdd(key, expiresAt);
        SweepIfDue(now);
        return Task.FromResult(added);
    }

    /// <summary>Removes every expired entry now.</summary>
    internal void Sweep(DateTimeOffset now)
    {
        foreach (var kv in _entries)
            if (kv.Value <= now)
                _entries.TryRemove(kv);
    }

    private void SweepIfDue(DateTimeOffset now)
    {
        var due = Interlocked.Read(ref _nextSweepTicks);
        if (now.UtcTicks < due ||
            Interlocked.CompareExchange(ref _nextSweepTicks, now.Add(SweepInterval).UtcTicks, due) != due)
            return;
        Sweep(now);
    }
}
