namespace NetOidc.Provider.Http;

/// <summary>
/// Names of the <see cref="System.Net.Http.IHttpClientFactory"/> clients the provider uses for
/// outbound requests. Hosts can add to their configuration, e.g.
/// <c>services.AddHttpClient(NetOidcHttpClients.Trusted).ConfigurePrimaryHttpMessageHandler(...)</c>
/// to trust a private CA. Keep redirects disabled; for <see cref="Untrusted"/> keep the
/// public-address connect callback.
/// </summary>
public static class NetOidcHttpClients
{
    /// <summary>Calls to URLs the operator configured (static clients' logout and CIBA endpoints).</summary>
    public const string Trusted = "NetOidc.BackChannelLogout";

    /// <summary>
    /// Calls to URLs supplied by clients or third parties (dynamic registrations, federation,
    /// Client ID Metadata Documents, <c>jwks_uri</c>, <c>request_uri</c>): public addresses only.
    /// </summary>
    public const string Untrusted = "NetOidc.BackChannelLogout.Untrusted";
}
