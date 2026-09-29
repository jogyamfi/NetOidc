using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Logout;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Stands in for the internet behind the provider's untrusted HttpClient: serves registered
/// documents by exact URL and records every request.
/// </summary>
internal sealed class FakeWeb : HttpMessageHandler
{
    private readonly ConcurrentDictionary<string, (string Content, string MediaType, TimeSpan? MaxAge)> _documents = new();

    public ConcurrentQueue<Uri> Requests { get; } = new();

    public void Serve(string url, string content, string mediaType = "application/json", TimeSpan? maxAge = null) =>
        _documents[url] = (content, mediaType, maxAge);

    public void Remove(string url) => _documents.TryRemove(url, out _);

    /// <summary>Creates a provider whose untrusted outbound requests are answered by this instance.</summary>
    public TestWebApp CreateApp(Action<ProviderOptions> configure) =>
        TestWebApp.Create(configure, builder =>
            builder.Services.AddHttpClient(BackChannelLogoutService.UntrustedHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => this));

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Enqueue(request.RequestUri!);
        if (!_documents.TryGetValue(request.RequestUri!.AbsoluteUri, out var document))
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(document.Content, System.Text.Encoding.UTF8, document.MediaType),
        };
        if (document.MaxAge is { } maxAge)
            response.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { MaxAge = maxAge };
        return Task.FromResult(response);
    }

    // The provider's HttpClientFactory owns handler lifetime; never dispose the shared instance.
    protected override void Dispose(bool disposing) { }
}
