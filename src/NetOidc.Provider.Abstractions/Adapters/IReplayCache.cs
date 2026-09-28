namespace NetOidc.Provider.Abstractions.Adapters;

/// <summary>
/// Records one-time identifiers (JWT <c>jti</c> values, nonces) to detect replay.
/// Replace the in-memory default with a shared store when running multiple instances.
/// </summary>
public interface IReplayCache
{
    /// <summary>
    /// Atomically records <paramref name="key"/> until <paramref name="expiresAt"/>.
    /// Returns <c>false</c> when the key was already recorded and has not expired (a replay).
    /// </summary>
    Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default);
}
