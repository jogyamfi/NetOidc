using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Http;

/// <summary>
/// In-process throttles that protect guessable secrets and unauthenticated endpoints.
/// Enforced inside the handlers, so they apply without the host adding rate-limiting middleware.
/// </summary>
public sealed class RequestThrottle : IDisposable
{
    private readonly PartitionedRateLimiter<string> _userCodeFailures;
    private readonly PartitionedRateLimiter<string>? _unauthenticated;

    public RequestThrottle(IOptions<ProviderOptions> options)
    {
        var opts = options.Value;

        _userCodeFailures = PartitionedRateLimiter.Create<string, string>(subject =>
            RateLimitPartition.GetFixedWindowLimiter(subject, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, opts.DeviceUserCodeMaxFailedAttempts),
                Window = TimeSpan.FromSeconds(Math.Max(1, opts.DeviceUserCodeFailureWindowSeconds)),
                QueueLimit = 0,
            }));

        if (opts.UnauthenticatedRequestsPerMinute > 0)
        {
            _unauthenticated = PartitionedRateLimiter.Create<string, string>(ip =>
                RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = opts.UnauthenticatedRequestsPerMinute,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                }));
        }
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="subject"/> has exhausted its failed user-code
    /// attempts for the current window (RFC 8628 §5.1 brute-force protection).
    /// </summary>
    public bool IsUserCodeEntryBlocked(string subject) =>
        (_userCodeFailures.GetStatistics(subject)?.CurrentAvailablePermits ?? 1) <= 0;

    /// <summary>Records a wrong or expired user code entered by <paramref name="subject"/>.</summary>
    public void RecordUserCodeFailure(string subject) =>
        _userCodeFailures.AttemptAcquire(subject).Dispose();

    /// <summary>
    /// Consumes one request from the caller's per-IP budget for unauthenticated endpoints.
    /// Returns <c>false</c> when the budget is exhausted.
    /// </summary>
    public bool TryAcquireUnauthenticated(HttpContext context)
    {
        if (_unauthenticated is null) return true;
        var key = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        using var lease = _unauthenticated.AttemptAcquire(key);
        return lease.IsAcquired;
    }

    /// <summary>The standard 429 response for an exhausted budget.</summary>
    public static IResult TooManyRequests(HttpContext context, int retryAfterSeconds = 60)
    {
        context.Response.Headers.RetryAfter = retryAfterSeconds.ToString();
        return Results.Json(Errors.OAuthError.InvalidRequest("too many requests; retry later"), statusCode: 429);
    }

    public void Dispose()
    {
        _userCodeFailures.Dispose();
        _unauthenticated?.Dispose();
    }
}
