using System.Net;
using System.Text.Json;
using System.Web;

namespace NetOidc.Provider.Tests;

public sealed class ImplicitFlowTests
{
    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ── response_type=token ────────────────────────────────────────────────────

    [Fact]
    public async Task ImplicitToken_ReturnsAccessTokenInFragment()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "alice");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=implicit-client&response_type=token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid+profile&state=s1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("#", location);

        var fragment = location[(location.IndexOf('#') + 1)..];
        var p = HttpUtility.ParseQueryString(fragment);
        Assert.NotEmpty(p["access_token"]!);
        Assert.Equal("Bearer", p["token_type"]);
        Assert.Equal("s1", p["state"]);
        // RFC 9207: iss must be present
        Assert.NotEmpty(p["iss"]!);
    }

    [Fact]
    public async Task ImplicitToken_NoRefreshToken()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "alice");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=implicit-client&response_type=token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid");

        var fragment = resp.Headers.Location!.ToString();
        Assert.DoesNotContain("refresh_token", fragment);
    }

    // ── response_type=id_token ─────────────────────────────────────────────────

    [Fact]
    public async Task ImplicitIdToken_ReturnsIdTokenInFragment()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "bob");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=implicit-client&response_type=id_token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=my-nonce&state=s2");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("#", location);

        var fragment = location[(location.IndexOf('#') + 1)..];
        var p = HttpUtility.ParseQueryString(fragment);
        Assert.NotEmpty(p["id_token"]!);
        Assert.Equal("s2", p["state"]);
    }

    [Fact]
    public async Task ImplicitIdToken_RejectsRequest_WhenNonceMissing()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "bob");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=implicit-client&response_type=id_token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid");

        // Error should be returned in fragment (default for implicit)
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
    }

    // ── response_type=token id_token ───────────────────────────────────────────

    [Fact]
    public async Task ImplicitTokenIdToken_ReturnsBothInFragment()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "carol");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=implicit-client" +
            "&response_type=token%20id_token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("#", location);

        var fragment = location[(location.IndexOf('#') + 1)..];
        var p = HttpUtility.ParseQueryString(fragment);
        Assert.NotEmpty(p["access_token"]!);
        Assert.NotEmpty(p["id_token"]!);
    }
}
