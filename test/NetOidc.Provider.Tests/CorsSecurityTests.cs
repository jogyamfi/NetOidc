using System.Net;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P2.8 (CORS scope and origins).</summary>
public sealed class CorsSecurityTests
{
    private const string RegisteredOrigin = "https://client.test.example.com";

    [Theory]
    [InlineData("/connect/token", "POST")]
    [InlineData("/connect/userinfo", "GET")]
    [InlineData("/connect/revoke", "POST")]
    [InlineData("/.well-known/openid-configuration", "GET")]
    public async Task BrowserFacingEndpoints_AllowRegisteredOrigin(string path, string method)
    {
        await using var app = TestWebApp.Create(o => o.CorsEnabled = true);

        var resp = await PreflightAsync(app, path, method, RegisteredOrigin);

        Assert.Equal(RegisteredOrigin, AllowedOrigin(resp));
    }

    [Fact]
    public async Task UnregisteredOrigin_IsNotAllowed()
    {
        await using var app = TestWebApp.Create(o => o.CorsEnabled = true);

        var resp = await PreflightAsync(app, "/connect/token", "POST", "https://evil.example.net");

        Assert.Null(AllowedOrigin(resp));
    }

    [Fact]
    public async Task ConfiguredOrigin_IsAllowed()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.CorsEnabled = true;
            o.CorsAllowedOrigins = ["https://spa.example.org"];
        });

        var resp = await PreflightAsync(app, "/connect/token", "POST", "https://spa.example.org");

        Assert.Equal("https://spa.example.org", AllowedOrigin(resp));
    }

    [Theory]
    [InlineData("/connect/authorize")]
    [InlineData("/connect/device")]
    [InlineData("/connect/introspect")]
    public async Task UserFacingAndServerEndpoints_DoNotEmitCorsHeaders(string path)
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.CorsEnabled = true;
            o.DeviceFlowEnabled = true;
        });

        var req = new HttpRequestMessage(HttpMethod.Get, path);
        req.Headers.Add("Origin", RegisteredOrigin);
        var resp = await app.Client.SendAsync(req);

        Assert.Null(AllowedOrigin(resp));
    }

    [Fact]
    public async Task RegistrationEndpoint_DoesNotAcceptCrossOriginPreflight()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.CorsEnabled = true;
            o.DcrEnabled = true;
        });

        var resp = await PreflightAsync(app, "/connect/register", "POST", RegisteredOrigin);

        Assert.Null(AllowedOrigin(resp));
    }

    private static Task<HttpResponseMessage> PreflightAsync(TestWebApp app, string path, string method, string origin)
    {
        var req = new HttpRequestMessage(HttpMethod.Options, path);
        req.Headers.Add("Origin", origin);
        req.Headers.Add("Access-Control-Request-Method", method);
        req.Headers.Add("Access-Control-Request-Headers", "authorization");
        return app.Client.SendAsync(req);
    }

    private static string? AllowedOrigin(HttpResponseMessage resp) =>
        resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var values) ? values.Single() : null;
}
