namespace NetOidc.Provider.Abstractions.Adapters;

/// <summary>
/// Pluggable store for a single model type. Implement this for any persistence
/// backend (EF Core, Redis, Postgres, â€¦).
/// </summary>
public interface IAdapter<T> where T : class
{
    /// <summary>Returns the entity or null if absent / expired.</summary>
    Task<T?> FindAsync(string id, CancellationToken ct = default);

    /// <summary>Persists the entity, optionally with a TTL.</summary>
    Task StoreAsync(string id, T entity, TimeSpan? expiresIn = null, CancellationToken ct = default);

    /// <summary>Removes the entity.</summary>
    Task RemoveAsync(string id, CancellationToken ct = default);

    /// <summary>Finds and atomically removes the entity (for one-time-use records like auth codes).</summary>
    Task<T?> ConsumeAsync(string id, CancellationToken ct = default);
}
