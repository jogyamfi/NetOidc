using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
    public async Task EndSession_WithoutHint_AsksForConfirmation()
    {
        await SignInAsync("user1");

        var resp = await _app.Client.GetAsync("/connect/end_session?state=s");

        // RP-Initiated Logout §2: no valid id_token_hint → the End-User must confirm.
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.StartsWith("/account/logout", resp.Headers.Location!.ToString());
        Assert.Contains("state=s", resp.Headers.Location!.ToString());
    }

    [Fact]
    public async Task EndSession_Confirmed_ShowsSignedOutPageWithoutRedirectUri()
    {
        await SignInAsync("user1b");

        var resp = await ConfirmLogoutAsync(_app, []);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("signed out", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task EndSession_ConfirmationWithoutAntiforgeryToken_IsRejected()
    {
        await SignInAsync("user1c");

        var resp = await _app.Client.PostAsync("/connect/end_session",
            new FormUrlEncodedContent([new("confirm", "true")]));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
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

        var resp = await ConfirmLogoutAsync(_app,
        [
            new("client_id", "test-client"),
            new("post_logout_redirect_uri", "https://client.test.example.com/logout"),
            new("state", "abc123"),
        ]);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location?.ToString() ?? "";
        Assert.Contains("https://client.test.example.com/logout", location);
        Assert.Contains("state=abc123", location);
    }

    [Fact]
    public async Task EndSession_Post_RedirectsToPostLogoutUri()
    {
        await SignInAsync("user3");

        var resp = await ConfirmLogoutAsync(_app,
        [
            new("client_id", "test-client"),
            new("post_logout_redirect_uri", "https://client.test.example.com/logout"),
        ]);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal("https://client.test.example.com/logout", resp.Headers.Location!.ToString());
    }

    // ── P1.1: open-redirect prevention ───────────────────────────────────────

    [Fact]
    public async Task EndSession_WithoutClient_DoesNotRedirectToArbitraryUri()
    {
        await SignInAsync("user-or1");

        var target = Uri.EscapeDataString("https://evil.example.net/phish");
        var resp = await _app.Client.GetAsync(
            $"/connect/end_session?post_logout_redirect_uri={target}");

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Null(resp.Headers.Location);
    }

    [Fact]
    public async Task EndSession_UnregisteredUri_ForKnownClient_IsRejected()
    {
        await SignInAsync("user-or2");

        var target = Uri.EscapeDataString("https://evil.example.net/phish");
        var resp = await _app.Client.GetAsync(
            $"/connect/end_session?client_id=test-client&post_logout_redirect_uri={target}");

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task EndSession_ClientWithNoRegisteredUris_IsRejected()
    {
        await SignInAsync("user-or3");

        var target = Uri.EscapeDataString("https://evil.example.net/phish");
        var resp = await _app.Client.GetAsync(
            $"/connect/end_session?client_id=implicit-client&post_logout_redirect_uri={target}");

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task EndSession_StateIsAppendedToExistingQuery()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.LogoutEnabled = true;
            opts.StaticClients =
            [
                .. opts.StaticClients,
                new Abstractions.Models.Client
                {
                    ClientId = "query-logout-client",
                    ClientSecret = "secret",
                    PostLogoutRedirectUris = ["https://client.test.example.com/logout?x=1"],
                },
            ];
        });

        var resp = await ConfirmLogoutAsync(app,
        [
            new("client_id", "query-logout-client"),
            new("post_logout_redirect_uri", "https://client.test.example.com/logout?x=1"),
            new("state", "s1"),
        ]);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal("https://client.test.example.com/logout?x=1&state=s1",
            resp.Headers.Location!.ToString());
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

    /// <summary>
    /// Posts a confirmed logout the way the host's confirmation page would: the original
    /// parameters plus <c>confirm=true</c> and an antiforgery token.
    /// </summary>
    internal static async Task<HttpResponseMessage> ConfirmLogoutAsync(
        TestWebApp app, List<KeyValuePair<string, string>> parameters)
    {
        var csrf = JsonDocument.Parse(await app.Client.GetStringAsync("/test/antiforgery")).RootElement;
        parameters.Add(new("confirm", "true"));
        parameters.Add(new(csrf.GetProperty("field").GetString()!, csrf.GetProperty("token").GetString()!));
        return await app.Client.PostAsync("/connect/end_session", new FormUrlEncodedContent(parameters));
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
