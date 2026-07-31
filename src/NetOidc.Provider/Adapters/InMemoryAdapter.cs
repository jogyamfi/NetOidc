using System.Collections.Concurrent;
using NetOidc.Provider.Abstractions.Adapters;

namespace NetOidc.Provider.Adapters;

/// <summary>Thread-safe in-memory adapter with optional TTL expiry.</summary>
public sealed class InMemoryAdapter<T> : IAdapter<T> where T : class
{
    private readonly ConcurrentDictionary<string, (T Entity, DateTimeOffset? ExpiresAt)> _store = new();

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
        var expiresAt = expiresIn.HasValue ? DateTimeOffset.UtcNow + expiresIn.Value : (DateTimeOffset?)null;
        _store[id] = (entity, expiresAt);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string id, CancellationToken ct = default)
    {
        _store.TryRemove(id, out _);
        return Task.CompletedTask;
    }

    public async Task<T?> ConsumeAsync(string id, CancellationToken ct = default)
    {
        var entity = await FindAsync(id, ct);
        if (entity is not null)
            _store.TryRemove(id, out _);
        return entity;
    }
}
