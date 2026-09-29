using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace NetOidc.Provider.Diagnostics;

/// <summary>
/// OpenTelemetry-compatible instrumentation. Subscribe with
/// <c>.AddSource(NetOidcTelemetry.Name)</c> for traces and <c>.AddMeter(NetOidcTelemetry.Name)</c>
/// for metrics. Tags never contain tokens, secrets or End-User identifiers.
/// </summary>
public static class NetOidcTelemetry
{
    public const string Name = "NetOidc.Provider";

    public static readonly ActivitySource ActivitySource = new(Name);

    private static readonly Meter Meter = new(Name);

    /// <summary>Tokens issued, tagged by <c>grant_type</c>.</summary>
    public static readonly Counter<long> TokensIssued =
        Meter.CreateCounter<long>("netoidc.tokens.issued", description: "Access tokens issued");

    /// <summary>Token requests rejected, tagged by <c>grant_type</c> and <c>error</c>.</summary>
    public static readonly Counter<long> TokenRequestsFailed =
        Meter.CreateCounter<long>("netoidc.token.requests.failed", description: "Token requests rejected");

    /// <summary>Authorization requests completed, tagged by <c>outcome</c> (success or the error code).</summary>
    public static readonly Counter<long> Authorizations =
        Meter.CreateCounter<long>("netoidc.authorizations", description: "Authorization requests completed");

    /// <summary>Failed client authentications, tagged by <c>endpoint</c>.</summary>
    public static readonly Counter<long> ClientAuthenticationFailures =
        Meter.CreateCounter<long>("netoidc.client_authentication.failures", description: "Failed client authentications");

    /// <summary>Endpoint processing time in milliseconds, tagged by <c>endpoint</c> and <c>status</c>.</summary>
    public static readonly Histogram<double> RequestDuration =
        Meter.CreateHistogram<double>("netoidc.request.duration", unit: "ms", description: "Endpoint processing time");
}
