using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Web;
using Xunit;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Integration tests for RP-Initiated Logout and Session management (Phase 3).
/// </summary>
public sealed class LogoutTests : IAsyncLifetime
{
    private TestWebApp _app = null!;

    public Task InitializeAsync()
    {
        _app = TestWebApp.Create(opts =>
        {
            opts.LogoutEnabled = true;
            opts.BackChannelLogoutEnabled = false;  // avoid network calls in tests
        });
        return Task.CompletedTask;
    }

    public Task DisposeAsync() => _app.DisposeAsync().AsTask();

    // ── end_session endpoint availability ───────────────────────────────────

    [Fact]
    public async Task EndSession_IsReachable_Returns204WithoutParams()
    {
        // Sign in first so there is a cookie session.
        await SignInAsync("user1");

        var resp = await _app.Client.GetAsync("/connect/end_session");
        // No post_logout_redirect_uri — should return 204.
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    [Fact]
    public async Task EndSession_NotMapped_When_LogoutDisabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.LogoutEnabled = false;
        });

        var resp = await app.Client.GetAsync("/connect/end_session");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── post_logout_redirect_uri ─────────────────────────────────────────────

    [Fact]
    public async Task EndSession_RedirectsToPostLogoutUri_WithState()
    {
        await SignInAsync("user2");

        var target = Uri.EscapeDataString("https://client.test.example.com/logout");
        var state = Uri.EscapeDataString("abc123");
        var resp = await _app.Client.GetAsync(
            $"/connect/end_session?post_logout_redirect_uri={target}&state={state}");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location?.ToString() ?? "";
        Assert.Contains("https://client.test.example.com/logout", location);
        Assert.Contains("state=abc123", location);
    }

    [Fact]
    public async Task EndSession_Post_RedirectsToPostLogoutUri()
    {
        await SignInAsync("user3");

        var form = new Dictionary<string, string>
        {
            ["post_logout_redirect_uri"] = "https://client.test.example.com/logout",
        };
        var resp = await _app.Client.PostAsync(
            "/connect/end_session", new FormUrlEncodedContent(form));

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
    }

    // ── Discovery document advertises end_session_endpoint ──────────────────

    [Fact]
    public async Task DiscoveryDocument_AdvertisesEndSessionEndpoint_WhenLogoutEnabled()
    {
        var resp = await _app.Client.GetAsync("/.well-known/openid-configuration");
        resp.EnsureSuccessStatusCode();

        var doc = await resp.Content.ReadFromJsonAsync<JsonObject>();
        var ep = doc!["end_session_endpoint"]?.GetValue<string>();
        Assert.NotNull(ep);
        Assert.Contains("/connect/end_session", ep);
    }

    [Fact]
    public async Task DiscoveryDocument_NoEndSessionEndpoint_WhenLogoutDisabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.LogoutEnabled = false;
        });

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var doc = await resp.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Null(doc!["end_session_endpoint"]);
    }

    // ── Session cookie and sid claim ─────────────────────────────────────────

    [Fact]
    public async Task AuthorizationFlow_SetsSessionCookie_WhenLogoutEnabled()
    {
        await SignInAsync("user4");

        // Start the auth code flow.
        var authResp = await _app.Client.GetAsync(
            "/connect/authorize?response_type=code" +
            "&client_id=test-client" +
            "&redirect_uri=https://client.test.example.com/callback" +
            "&scope=openid+profile" +
            "&state=st1");

        // Should redirect with code (not error).
        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var location = authResp.Headers.Location?.ToString() ?? "";
        Assert.Contains("code=", location);

        // The provider should have set the session cookie.
        var setCookie = authResp.Headers
            .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .SelectMany(h => h.Value)
            .FirstOrDefault(v => v.Contains("netoidc.sid"));
        Assert.NotNull(setCookie);
    }

    [Fact]
    public async Task IdToken_ContainsSidClaim_WhenLogoutEnabled()
    {
        await SignInAsync("user5");

        // Get auth code.
        var authResp = await _app.Client.GetAsync(
            "/connect/authorize?response_type=code" +
            "&client_id=test-client" +
            "&redirect_uri=https://client.test.example.com/callback" +
            "&scope=openid+profile" +
            "&state=st2");

        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var location = authResp.Headers.Location!.ToString();
        var qs = HttpUtility.ParseQueryString(new Uri(location).Query);
        var code = qs["code"];
        Assert.NotNull(code);

        // Exchange code for tokens.
        var tokenForm = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = "https://client.test.example.com/callback",
            ["client_id"] = "test-client",
        };
        var tokenReqMsg = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(tokenForm),
            Headers =
            {
                Authorization = new("Basic",
                    Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes("test-client:test-secret"))),
            },
        };
        var tokenRespMsg = await _app.Client.SendAsync(tokenReqMsg);
        Assert.Equal(HttpStatusCode.OK, tokenRespMsg.StatusCode);

        var body = await tokenRespMsg.Content.ReadFromJsonAsync<JsonObject>();
        var idTokenJwt = body!["id_token"]?.GetValue<string>();
        Assert.NotNull(idTokenJwt);

        // Decode the JWT payload (no signature verification needed here).
        var parts = idTokenJwt!.Split('.');
        var payload = System.Text.Json.JsonDocument.Parse(
            System.Text.Encoding.UTF8.GetString(
                Convert.FromBase64String(PadBase64(parts[1]))));

        Assert.True(payload.RootElement.TryGetProperty("sid", out var sidProp));
        Assert.NotEmpty(sidProp.GetString()!);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private async Task SignInAsync(string subject)
    {
        var resp = await _app.Client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    private static string PadBase64(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return (s.Length % 4) switch
        {
            2 => s + "==",
            3 => s + "=",
            _ => s,
        };
    }
}
