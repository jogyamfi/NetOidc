using System.Collections.Concurrent;
using NetOidc.Provider.Abstractions.Adapters;

namespace NetOidc.Provider.Adapters;

/// <summary>
/// Thread-safe in-memory adapter with optional TTL expiry. Expired entries are swept
/// periodically so abandoned codes and tokens do not accumulate.
/// </summary>
public sealed class InMemoryAdapter<T> : IAdapter<T> where T : class
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, (T Entity, DateTimeOffset? ExpiresAt)> _store = new();
    private long _nextSweepTicks = DateTimeOffset.UtcNow.Add(SweepInterval).UtcTicks;

    /// <summary>Number of entries currently held, including not-yet-swept expired ones.</summary>
    internal int Count => _store.Count;

    public Task<T?> FindAsync(string id, CancellationToken ct = default)
    {
        if (_store.TryGetValue(id, out var entry))
        {
            if (entry.ExpiresAt is null || entry.ExpiresAt > DateTimeOffset.UtcNow)
                return Task.FromResult<T?>(entry.Entity);

            _store.TryRemove(id, out _);
        }

        return Task.FromResult<T?>(null);
    }

    public Task StoreAsync(string id, T entity, TimeSpan? expiresIn = null, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = expiresIn.HasValue ? now + expiresIn.Value : (DateTimeOffset?)null;
        _store[id] = (entity, expiresAt);
        SweepIfDue(now);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string id, CancellationToken ct = default)
    {
        _store.TryRemove(id, out _);
        return Task.CompletedTask;
    }

    public Task<T?> ConsumeAsync(string id, CancellationToken ct = default)
    {
        // TryRemove is the single atomic step: exactly one caller can win the entry.
        if (!_store.TryRemove(id, out var entry))
            return Task.FromResult<T?>(null);

        return Task.FromResult(
            entry.ExpiresAt is null || entry.ExpiresAt > DateTimeOffset.UtcNow ? entry.Entity : null);
    }

    /// <summary>Removes every expired entry now.</summary>
    internal void Sweep(DateTimeOffset now)
    {
        foreach (var kv in _store)
            if (kv.Value.ExpiresAt is { } expiresAt && expiresAt <= now)
                _store.TryRemove(kv);
    }

    private void SweepIfDue(DateTimeOffset now)
    {
        var due = Interlocked.Read(ref _nextSweepTicks);
        // Only the caller that advances the deadline performs the sweep.
        if (now.UtcTicks < due ||
            Interlocked.CompareExchange(ref _nextSweepTicks, now.Add(SweepInterval).UtcTicks, due) != due)
            return;
        Sweep(now);
    }
}
