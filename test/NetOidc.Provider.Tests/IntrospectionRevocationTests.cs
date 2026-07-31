using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;

namespace NetOidc.Provider.Tests;

public sealed class IntrospectionRevocationTests
{
    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    private static async Task<string> GetTokenAsync(
        HttpClient client, string clientId, string secret)
    {
        await SignInAsync(client, "alice");
        var authResp = await client.GetAsync(
            $"/connect/authorize?client_id={clientId}&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid+profile");
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        req.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth(clientId, secret));
        req.Content = new FormUrlEncodedContent([
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", "https://client.test.example.com/callback"),
        ]);
        var tokenResp = await client.SendAsync(req);
        var body = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync()).RootElement;
        return body.GetProperty("access_token").GetString()!;
    }

    // ── Introspection ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Introspection_ReturnsActive_ForValidToken()
    {
        await using var app = TestWebApp.Create();
        var accessToken = await GetTokenAsync(app.Client, "test-client", "test-secret");

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/introspect");
        req.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret"));
        req.Content = new FormUrlEncodedContent([new("token", accessToken)]);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(body.GetProperty("active").GetBoolean());
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task Introspection_ReturnsInactive_ForGarbageToken()
    {
        await using var app = TestWebApp.Create();

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/introspect");
        req.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret"));
        req.Content = new FormUrlEncodedContent([new("token", "garbage.not.a.jwt")]);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(body.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Introspection_RequiresClientAuth()
    {
        await using var app = TestWebApp.Create();

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/introspect");
        req.Content = new FormUrlEncodedContent([new("token", "any")]);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Revocation ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Revocation_Returns200_ForValidToken()
    {
        await using var app = TestWebApp.Create();
        var accessToken = await GetTokenAsync(app.Client, "test-client", "test-secret");

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/revoke");
        req.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret"));
        req.Content = new FormUrlEncodedContent([
            new("token", accessToken),
            new("token_type_hint", "access_token"),
        ]);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Revocation_Returns200_ForUnknownToken()
    {
        // RFC 7009 §2.2: server must respond 200 even if token not found
        await using var app = TestWebApp.Create();

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/revoke");
        req.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret"));
        req.Content = new FormUrlEncodedContent([new("token", "nonexistent-token")]);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Revocation_TokenIsInactiveAfterRevocation()
    {
        await using var app = TestWebApp.Create();
        var accessToken = await GetTokenAsync(app.Client, "test-client", "test-secret");

        // Revoke
        var revokeReq = new HttpRequestMessage(HttpMethod.Post, "/connect/revoke");
        revokeReq.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret"));
        revokeReq.Content = new FormUrlEncodedContent([new("token", accessToken)]);
        var revokeResp = await app.Client.SendAsync(revokeReq);
        Assert.Equal(HttpStatusCode.OK, revokeResp.StatusCode);

        // Introspect — should now be inactive
        var introReq = new HttpRequestMessage(HttpMethod.Post, "/connect/introspect");
        introReq.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret"));
        introReq.Content = new FormUrlEncodedContent([new("token", accessToken)]);
        var introResp = await app.Client.SendAsync(introReq);

        var body = JsonDocument.Parse(await introResp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(body.GetProperty("active").GetBoolean());
    }
}
