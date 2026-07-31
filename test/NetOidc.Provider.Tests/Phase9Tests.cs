using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Integration tests for Phase 9: events/hooks system, event sink registration,
/// NuGet packaging metadata, and security hardening.
/// </summary>
public sealed class Phase9Tests
{
    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Events / hooks system
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task TokenIssuedEvent_FiredOn_AuthorizationCodeGrant()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        await SignInAsync(app.Client, "alice");

        // Get auth code
        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid+profile");
        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        // Exchange code for token
        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", "https://client.test.example.com/callback"),
            ]),
        });
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);

        Assert.Single(sink.TokensIssued);
        Assert.Equal("test-client", sink.TokensIssued[0].ClientId);
        Assert.Equal("authorization_code", sink.TokensIssued[0].GrantType);
        Assert.Contains("openid", sink.TokensIssued[0].Scopes);
    }

    [Fact]
    public async Task TokenIssuedEvent_FiredOn_ClientCredentialsGrant()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        var resp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        Assert.Single(sink.TokensIssued);
        Assert.Equal("cc-client", sink.TokensIssued[0].ClientId);
        Assert.Equal("client_credentials", sink.TokensIssued[0].GrantType);
        Assert.Null(sink.TokensIssued[0].Subject);
    }

    [Fact]
    public async Task TokenIssuedEvent_FiredOn_RefreshTokenGrant()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        await SignInAsync(app.Client, "bob");

        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid+profile");
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", "https://client.test.example.com/callback"),
            ]),
        });
        var tokenBody = await tokenResp.Content.ReadAsStringAsync();
        var refreshToken = System.Text.Json.JsonDocument.Parse(tokenBody)
            .RootElement.GetProperty("refresh_token").GetString()!;

        // Clear events so we only check the refresh-token event
        sink.TokensIssued.Clear();

        var refreshResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "refresh_token"),
                new("refresh_token", refreshToken),
            ]),
        });
        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);

        Assert.Single(sink.TokensIssued);
        Assert.Equal("refresh_token", sink.TokensIssued[0].GrantType);
    }

    [Fact]
    public async Task AuthorizationSucceededEvent_Fired_WhenAuthorizationCompletes()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        await SignInAsync(app.Client, "alice");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid+profile");
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);

        Assert.Single(sink.AuthorizationsSucceeded);
        Assert.Equal("test-client", sink.AuthorizationsSucceeded[0].ClientId);
        Assert.Contains("openid", sink.AuthorizationsSucceeded[0].GrantedScopes);
    }

    [Fact]
    public async Task TokenIntrospectedEvent_Fired_WhenIntrospectionCalled()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        // Obtain an access token via client_credentials
        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        });
        var accessToken = System.Text.Json.JsonDocument.Parse(
            await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        // Introspect
        var introResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/introspect")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([new("token", accessToken)]),
        });
        Assert.Equal(HttpStatusCode.OK, introResp.StatusCode);

        Assert.Single(sink.TokensIntrospected);
        Assert.Equal("cc-client", sink.TokensIntrospected[0].CallerClientId);
        Assert.True(sink.TokensIntrospected[0].Active);
    }

    [Fact]
    public async Task TokenRevokedEvent_Fired_WhenRevocationCalled()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        });
        var accessToken = System.Text.Json.JsonDocument.Parse(
            await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        var revokeResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/revoke")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([new("token", accessToken)]),
        });
        Assert.Equal(HttpStatusCode.OK, revokeResp.StatusCode);

        Assert.Single(sink.TokensRevoked);
        Assert.Equal("cc-client", sink.TokensRevoked[0].CallerClientId);
    }

    [Fact]
    public async Task UserInfoRequestedEvent_Fired_WhenUserInfoCalled()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        await SignInAsync(app.Client, "alice");

        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid+profile");
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", "https://client.test.example.com/callback"),
            ]),
        });
        var accessToken = System.Text.Json.JsonDocument.Parse(
            await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        // Call UserInfo
        var uiResp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Get, "/connect/userinfo")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken) },
        });
        Assert.Equal(HttpStatusCode.OK, uiResp.StatusCode);

        Assert.Single(sink.UserInfoRequests);
        Assert.Equal("alice", sink.UserInfoRequests[0].Subject);
    }

    [Fact]
    public async Task AddEventSink_WithInstance_RegistersCustomSink()
    {
        var sink = new CapturingEventSink();
        await using var app = TestWebApp.Create(
            configure: null,
            configureBuilder: b => b.AddEventSink(sink));

        // Verify our custom sink is the registered IProviderEventSink
        var resolved = app.Services.GetService(typeof(IProviderEventSink));
        Assert.Same(sink, resolved);
    }

    [Fact]
    public async Task DefaultEventSink_IsNoOp_WhenNotConfigured()
    {
        // No custom sink registered — provider should still work without error
        await using var app = TestWebApp.Create();

        var resp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Security hardening
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Authorization_RejectsUnknownRedirectUri_WithErrorPage()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "alice");

        // redirect_uri not registered for the client
        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fattacker.example.com%2Fcb" +
            "&scope=openid");

        // Must NOT redirect to an unregistered URI (open redirect prevention)
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Token_RejectsWrongClientSecret()
    {
        await using var app = TestWebApp.Create();

        var resp = await app.Client.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:WRONG"))) },
            Content = new FormUrlEncodedContent([
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Token_RejectsAuthCodeReuse()
    {
        await using var app = TestWebApp.Create();
        await SignInAsync(app.Client, "alice");

        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid");
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        var form = new FormUrlEncodedContent([
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", "https://client.test.example.com/callback"),
        ]);

        var headers = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));

        // First use should succeed
        var req1 = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            { Content = form, Headers = { Authorization = headers } };
        var resp1 = await app.Client.SendAsync(req1);
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);

        // Reuse the same code — must fail (replay attack prevention)
        var req2 = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = headers },
            Content = new FormUrlEncodedContent([
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", "https://client.test.example.com/callback"),
            ]),
        };
        var resp2 = await app.Client.SendAsync(req2);
        Assert.Equal(HttpStatusCode.BadRequest, resp2.StatusCode);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Packaging / versioning
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public void NetOidcBuilder_AddEventSink_ReturnsBuilderForChaining()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        // AddNetOidc returns a NetOidcBuilder; verify AddEventSink chains
        var builder = services.AddNetOidc(_ => { });
        var returned = builder.AddEventSink<NoOpSink>();
        Assert.Same(builder, returned);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Helpers — test doubles
    // ════════════════════════════════════════════════════════════════════════════

    private sealed class CapturingEventSink : IProviderEventSink
    {
        public List<TokenIssuedEvent> TokensIssued { get; } = [];
        public List<AuthorizationSucceededEvent> AuthorizationsSucceeded { get; } = [];
        public List<TokenIntrospectedEvent> TokensIntrospected { get; } = [];
        public List<TokenRevokedEvent> TokensRevoked { get; } = [];
        public List<UserInfoRequestedEvent> UserInfoRequests { get; } = [];

        public Task TokenIssuedAsync(TokenIssuedEvent e, CancellationToken ct = default)
        { TokensIssued.Add(e); return Task.CompletedTask; }

        public Task AuthorizationSucceededAsync(AuthorizationSucceededEvent e, CancellationToken ct = default)
        { AuthorizationsSucceeded.Add(e); return Task.CompletedTask; }

        public Task TokenIntrospectedAsync(TokenIntrospectedEvent e, CancellationToken ct = default)
        { TokensIntrospected.Add(e); return Task.CompletedTask; }

        public Task TokenRevokedAsync(TokenRevokedEvent e, CancellationToken ct = default)
        { TokensRevoked.Add(e); return Task.CompletedTask; }

        public Task UserInfoRequestedAsync(UserInfoRequestedEvent e, CancellationToken ct = default)
        { UserInfoRequests.Add(e); return Task.CompletedTask; }
    }

    private sealed class NoOpSink : IProviderEventSink
    {
        public Task TokenIssuedAsync(TokenIssuedEvent e, CancellationToken ct = default) => Task.CompletedTask;
        public Task AuthorizationSucceededAsync(AuthorizationSucceededEvent e, CancellationToken ct = default) => Task.CompletedTask;
        public Task TokenIntrospectedAsync(TokenIntrospectedEvent e, CancellationToken ct = default) => Task.CompletedTask;
        public Task TokenRevokedAsync(TokenRevokedEvent e, CancellationToken ct = default) => Task.CompletedTask;
        public Task UserInfoRequestedAsync(UserInfoRequestedEvent e, CancellationToken ct = default) => Task.CompletedTask;
    }
}

/// <summary>Extension to register a specific <see cref="IProviderEventSink"/> instance.</summary>
internal static class NetOidcBuilderTestExtensions
{
    public static NetOidcBuilder AddEventSink(this NetOidcBuilder builder, IProviderEventSink sink)
    {
        builder.Services.AddSingleton(sink);
        return builder;
    }
}
