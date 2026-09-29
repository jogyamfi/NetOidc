using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Diagnostics;

/// <summary>
/// Reports the state of the provider's signing keys: unhealthy with no active signing key,
/// degraded when keys are generated or every active signing key expires within the warning
/// window and no successor is published.
/// </summary>
public sealed class KeyHealthCheck : IHealthCheck
{
    private readonly IKeyStore _store;
    private readonly TimeSpan _warnBefore;

    public KeyHealthCheck(IKeyStore store, TimeSpan warnBefore)
    {
        _store = store;
        _warnBefore = warnBefore;
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var signing = _store.GetKeys().Where(k => k.Use == ProviderKeyUse.Signing).ToList();
        var active = signing.Where(k => k.IsActive(now)).ToList();
        var data = new Dictionary<string, object>
        {
            ["active_signing_keys"] = active.Count,
            ["published_signing_keys"] = signing.Count(k => k.IsPublished(now)),
        };

        if (active.Count == 0)
            return Task.FromResult(HealthCheckResult.Unhealthy("No active signing key.", data: data));

        if (signing.Any(k => k.IsGenerated))
            return Task.FromResult(HealthCheckResult.Degraded("Using generated keys (development only).", data: data));

        var horizon = now + _warnBefore;
        var allExpiring = active.All(k => k.NotAfter is { } notAfter && notAfter <= horizon);
        var successorQueued = signing.Any(k => k.NotBefore > now && (k.NotAfter is null || k.NotAfter > horizon));
        if (allExpiring && !successorQueued)
            return Task.FromResult(HealthCheckResult.Degraded(
                $"All active signing keys expire within {_warnBefore.TotalDays:0.#} days and no successor is published.",
                data: data));

        return Task.FromResult(HealthCheckResult.Healthy(data: data));
    }
}

/// <summary>Health-check registration.</summary>
public static class NetOidcHealthCheckExtensions
{
    /// <summary>
    /// Adds the <c>netoidc_keys</c> health check (see <see cref="KeyHealthCheck"/>).
    /// <paramref name="warnBefore"/> defaults to 7 days.
    /// </summary>
    public static IHealthChecksBuilder AddNetOidcKeys(
        this IHealthChecksBuilder builder, TimeSpan? warnBefore = null, string name = "netoidc_keys") =>
        builder.Add(new HealthCheckRegistration(
            name,
            sp => new KeyHealthCheck(sp.GetRequiredService<IKeyStore>(), warnBefore ?? TimeSpan.FromDays(7)),
            failureStatus: null,
            tags: ["netoidc"]));
}
