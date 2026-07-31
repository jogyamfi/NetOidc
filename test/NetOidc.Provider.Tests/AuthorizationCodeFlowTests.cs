using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Tests;

public sealed class AuthorizationCodeFlowTests
{
    // ── Helpers ────────────────────────────────────────────────────────────────

    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    private static (string Verifier, string Challenge) CreatePkceS256()
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Base64UrlEncoder.Encode(hash);
        return (verifier, challenge);
    }

    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    // ── Tests ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Authorize_RedirectsToLogin_WhenNotAuthenticated()
    {
        await using var app = TestWebApp.Create();

        var response = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid");

        // Should redirect to the login path (may chain to full URL or just path)
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location?.ToString() ?? "";
        Assert.Contains("/test/signin", location);
    }

    [Fact]
    public async Task Authorize_ReturnsCode_WhenAuthenticated()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "alice");

        var response = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&state=xyz");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        var qs = HttpUtility.ParseQueryString(new Uri(location).Query);
        Assert.NotEmpty(qs["code"]!);
        Assert.Equal("xyz", qs["state"]);
    }

    [Fact]
    public async Task Authorize_ReturnsError_ForUnknownClient()
    {
        await using var app = TestWebApp.Create();

        var response = await app.Client.GetAsync(
            "/connect/authorize?client_id=unknown&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback");

        // Must NOT redirect when client is unknown — return an error page
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task FullFlow_AuthCode_TokenExchange_UserInfo()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "bob");

        // Step 1: get authorization code
        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid+profile&state=s1");

        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;
        Assert.NotEmpty(code);

        // Step 2: exchange code for tokens
        var tokenReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        tokenReq.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        tokenReq.Content = new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", "https://client.test.example.com/callback"),
        ]);

        var tokenResp = await app.Client.SendAsync(tokenReq);
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);

        var tokenJson = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        var accessToken = tokenJson.RootElement.GetProperty("access_token").GetString()!;
        var idToken = tokenJson.RootElement.GetProperty("id_token").GetString()!;
        Assert.Equal("Bearer", tokenJson.RootElement.GetProperty("token_type").GetString());
        Assert.NotEmpty(accessToken);
        Assert.NotEmpty(idToken);

        // Step 3: call UserInfo
        var userInfoReq = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var userInfoResp = await app.Client.SendAsync(userInfoReq);

        Assert.Equal(HttpStatusCode.OK, userInfoResp.StatusCode);
        var userInfoJson = JsonDocument.Parse(await userInfoResp.Content.ReadAsStringAsync());
        Assert.Equal("bob", userInfoJson.RootElement.GetProperty("sub").GetString());
        Assert.Equal("Test bob", userInfoJson.RootElement.GetProperty("name").GetString());
    }

    [Fact]
    public async Task FullFlow_WithPkceS256()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.StaticClients =
            [
                new Client
                {
                    ClientId = "test-client",
                    ClientSecret = "test-secret",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = true,
                }
            ];
        });

        await SignInAsync(app.Client, "carol");

        var (verifier, challenge) = CreatePkceS256();

        // Authorize with PKCE
        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            $"&scope=openid&code_challenge={Uri.EscapeDataString(challenge)}" +
            "&code_challenge_method=S256");

        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        // Token exchange with correct verifier
        var tokenReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        tokenReq.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        tokenReq.Content = new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", "https://client.test.example.com/callback"),
            new("code_verifier", verifier),
        ]);

        var tokenResp = await app.Client.SendAsync(tokenReq);
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
    }

    [Fact]
    public async Task TokenEndpoint_RejectsWrongCodeVerifier()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.StaticClients =
            [
                new Client
                {
                    ClientId = "test-client",
                    ClientSecret = "test-secret",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = true,
                }
            ];
        });

        await SignInAsync(app.Client, "dave");

        var (_, challenge) = CreatePkceS256();

        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            $"&scope=openid&code_challenge={Uri.EscapeDataString(challenge)}" +
            "&code_challenge_method=S256");

        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        var tokenReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        tokenReq.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        tokenReq.Content = new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", "https://client.test.example.com/callback"),
            new("code_verifier", "wrong-verifier-that-does-not-match"),
        ]);

        var tokenResp = await app.Client.SendAsync(tokenReq);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResp.StatusCode);

        var errJson = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", errJson.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RefreshTokenGrant_IssuesNewAccessToken()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "erin");

        // Get initial tokens
        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback&scope=openid");

        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        var tokenReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        tokenReq.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        tokenReq.Content = new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", "https://client.test.example.com/callback"),
        ]);

        var tokenResp = await app.Client.SendAsync(tokenReq);
        var tokenJson = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        var refreshToken = tokenJson.RootElement.GetProperty("refresh_token").GetString()!;

        // Use refresh token
        var refreshReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        refreshReq.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        refreshReq.Content = new FormUrlEncodedContent(
        [
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken),
        ]);

        var refreshResp = await app.Client.SendAsync(refreshReq);
        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);

        var newJson = JsonDocument.Parse(await refreshResp.Content.ReadAsStringAsync());
        Assert.NotEmpty(newJson.RootElement.GetProperty("access_token").GetString()!);
        // New refresh token (rotation)
        var newRefreshToken = newJson.RootElement.GetProperty("refresh_token").GetString()!;
        Assert.NotEmpty(newRefreshToken);
        Assert.NotEqual(refreshToken, newRefreshToken);

        // Old refresh token must be consumed (replay rejected)
        var replayReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        replayReq.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        replayReq.Content = new FormUrlEncodedContent(
        [
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken),
        ]);
        var replayResp = await app.Client.SendAsync(replayReq);
        Assert.Equal(HttpStatusCode.BadRequest, replayResp.StatusCode);
    }
}
