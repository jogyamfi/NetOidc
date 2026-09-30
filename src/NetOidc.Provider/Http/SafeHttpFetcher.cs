using System.Net;
using System.Net.Http.Headers;
using NetOidc.Provider.Logout;

namespace NetOidc.Provider.Http;

/// <summary>A document fetched from a URL supplied by an untrusted party.</summary>
/// <param name="MaxAge">The response's <c>Cache-Control: max-age</c>, if any.</param>
internal sealed record FetchedDocument(string Content, string? MediaType, TimeSpan? MaxAge);

/// <summary>
/// Fetches documents named by untrusted parties (client metadata documents, federation entity
/// statements, JWKS): https only, no redirects, a connector that refuses non-public addresses,
/// a timeout and a response size limit.
/// </summary>
internal sealed class SafeHttpFetcher
{
    private readonly IHttpClientFactory _httpClientFactory;

    public SafeHttpFetcher(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    /// <summary>
    /// GETs <paramref name="url"/>. Returns <c>null</c> for non-https URLs, network failures,
    /// non-success responses and bodies larger than <paramref name="maxBytes"/>.
    /// <paramref name="allowPrivateNetwork"/> lifts the public-address restriction (never
    /// redirects, size limits or https), for deployments that trust their clients' URLs.
    /// </summary>
    public async Task<FetchedDocument?> GetAsync(
        string url, int maxBytes, string? accept, CancellationToken ct, bool allowPrivateNetwork = false)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.Fragment))
            return null;

        try
        {
            var http = _httpClientFactory.CreateClient(allowPrivateNetwork
                ? BackChannelLogoutService.TrustedHttpClientName
                : BackChannelLogoutService.UntrustedHttpClientName);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (accept is not null) request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(accept));

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode != HttpStatusCode.OK)
                return null;
            if (response.Content.Headers.ContentLength > maxBytes)
                return null;

            // Read at most maxBytes + 1 so an unannounced oversized body is detected.
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[maxBytes + 1];
            var read = 0;
            int n;
            while (read < buffer.Length && (n = await stream.ReadAsync(buffer.AsMemory(read), ct)) > 0)
                read += n;
            if (read > maxBytes)
                return null;

            return new FetchedDocument(
                System.Text.Encoding.UTF8.GetString(buffer, 0, read),
                response.Content.Headers.ContentType?.MediaType,
                response.Headers.CacheControl?.MaxAge);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            return null;
        }
    }
}
