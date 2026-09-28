using NetOidc.Provider.Http;

namespace NetOidc.Provider.Dcr;

/// <summary>
/// Validates URI-valued client metadata submitted through Dynamic Client Registration
/// (RFC 7591 §2, OIDC Registration §2, RFC 8252 §7 for native apps).
/// </summary>
internal static class ClientMetadataValidator
{
    /// <summary>Returns an error description, or <c>null</c> when the redirect URI is acceptable.</summary>
    public static string? ValidateRedirectUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return $"'{value}' is not an absolute URI";
        if (!string.IsNullOrEmpty(uri.Fragment) || value.Contains('#'))
            return $"'{value}' must not contain a fragment";

        switch (uri.Scheme)
        {
            case "https":
                return null;
            case "http":
                // RFC 8252 §7.3: plain http is only acceptable for loopback redirects.
                return uri.IsLoopback ? null : $"'{value}' must use https (http is allowed for loopback only)";
            default:
                // RFC 8252 §7.1: private-use schemes use reverse-domain notation (contain a dot).
                // This also excludes javascript:, data:, file:, vbscript: and similar.
                return uri.Scheme.Contains('.') && !string.IsNullOrEmpty(uri.AbsolutePath.Trim('/'))
                    ? null
                    : $"'{value}' uses a disallowed scheme '{uri.Scheme}'";
        }
    }

    /// <summary>Validates an informational http(s) URL such as <c>logo_uri</c> or <c>client_uri</c>.</summary>
    public static string? ValidateWebUri(string field, string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http"))
            return $"{field} must be an absolute http(s) URL";
        return null;
    }

    /// <summary>
    /// Validates a URL the provider itself will call (e.g. <c>backchannel_logout_uri</c>).
    /// </summary>
    public static string? ValidateServerCallbackUri(string field, string value, bool allowPrivateNetwork)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return $"{field} must be an absolute URI";
        if (!string.IsNullOrEmpty(uri.Fragment))
            return $"{field} must not contain a fragment";
        if (uri.Scheme != "https" && !(allowPrivateNetwork && uri.Scheme == "http"))
            return $"{field} must use https";
        if (!allowPrivateNetwork && NetworkAddressPolicy.IsObviouslyInternalHost(uri.Host))
            return $"{field} must not target a private or loopback address";
        return null;
    }
}
