namespace NetOidc.Provider.Token;

/// <summary>
/// How long device codes and CIBA requests are kept after they expire, so that polling clients
/// get <c>expired_token</c> (RFC 8628 §3.5, CIBA Core §11) instead of <c>invalid_grant</c>.
/// Expiry is enforced from the record's own <c>ExpiresAt</c>, not from the store's TTL.
/// </summary>
internal static class ExpiredRecords
{
    public static readonly TimeSpan Retention = TimeSpan.FromMinutes(10);

    /// <summary>Store TTL for a record that expires at <paramref name="expiresAt"/>.</summary>
    public static TimeSpan TimeToLive(DateTimeOffset expiresAt) =>
        (expiresAt - DateTimeOffset.UtcNow is var left && left > TimeSpan.Zero ? left : TimeSpan.Zero) + Retention;
}
