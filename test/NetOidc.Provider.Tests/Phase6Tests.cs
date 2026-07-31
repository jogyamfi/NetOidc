using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using Microsoft.Extensions.DependencyInjection;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Integration tests for Phase 6: Device Authorization Grant (RFC 8628) and
/// CIBA poll mode (OpenID CIBA Core 1.0).
/// </summary>
public sealed class Phase6Tests
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
    // Device Authorization Grant (RFC 8628)
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Device_Authorization_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // DeviceFlowEnabled = false

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent([new("scope", "openid profile")]),
        });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Device_Authorization_IssuesDeviceCode_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.DeviceFlowEnabled = true);

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent([new("scope", "openid profile")]),
        });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        Assert.True(body.RootElement.TryGetProperty("device_code", out var dc) && !string.IsNullOrEmpty(dc.GetString()));
        Assert.True(body.RootElement.TryGetProperty("user_code", out var uc) && !string.IsNullOrEmpty(uc.GetString()));
        Assert.True(body.RootElement.TryGetProperty("verification_uri", out _));
        Assert.True(body.RootElement.TryGetProperty("verification_uri_complete", out _));
        Assert.Equal(600, body.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal(5, body.RootElement.GetProperty("interval").GetInt32());
    }

    [Fact]
    public async Task Device_Token_Returns400_AuthorizationPending_BeforeUserActs()
    {
        await using var app = TestWebApp.Create(opts => opts.DeviceFlowEnabled = true);

        // Obtain device_code
        var authResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent([new("scope", "openid profile")]),
        });
        var authBody = JsonDocument.Parse(await authResp.Content.ReadAsStringAsync());
        var deviceCode = authBody.RootElement.GetProperty("device_code").GetString()!;

        // Poll immediately — user has not acted yet
        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                new("device_code", deviceCode),
            ]),
        });

        Assert.Equal(HttpStatusCode.BadRequest, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.Equal("authorization_pending", tokenBody.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Device_Token_IssuesTokens_AfterUserApproves()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DeviceFlowEnabled = true;
            opts.DevicePollingIntervalSeconds = 0; // no throttle in tests
        });

        // Obtain device_code
        var authResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent([new("scope", "openid profile")]),
        });
        var authBody = JsonDocument.Parse(await authResp.Content.ReadAsStringAsync());
        var deviceCode = authBody.RootElement.GetProperty("device_code").GetString()!;
        var userCodeFormatted = authBody.RootElement.GetProperty("user_code").GetString()!;

        // User signs in and approves via the verification endpoint
        await SignInAsync(app.Client, "device-user");
        var verifyResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device")
        {
            Content = new FormUrlEncodedContent(
            [
                new("user_code", userCodeFormatted),
                new("action", "approve"),
            ]),
        });
        Assert.Equal(HttpStatusCode.OK, verifyResp.StatusCode);

        // Poll token endpoint — should now succeed
        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                new("device_code", deviceCode),
            ]),
        });

        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.True(tokenBody.RootElement.TryGetProperty("access_token", out _));
        Assert.True(tokenBody.RootElement.TryGetProperty("id_token", out _));
    }

    [Fact]
    public async Task Device_Token_Returns400_AccessDenied_AfterUserDenies()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DeviceFlowEnabled = true;
            opts.DevicePollingIntervalSeconds = 0;
        });

        var authResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent([new("scope", "openid profile")]),
        });
        var authBody = JsonDocument.Parse(await authResp.Content.ReadAsStringAsync());
        var deviceCode = authBody.RootElement.GetProperty("device_code").GetString()!;
        var userCodeFormatted = authBody.RootElement.GetProperty("user_code").GetString()!;

        await SignInAsync(app.Client, "device-user-deny");
        await app.Client.PostAsync("/connect/device", new FormUrlEncodedContent(
        [
            new("user_code", userCodeFormatted),
            new("action", "deny"),
        ]));

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("device-client", "device-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                new("device_code", deviceCode),
            ]),
        });

        Assert.Equal(HttpStatusCode.BadRequest, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.Equal("access_denied", tokenBody.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Device_Discovery_AdvertisesEndpoint_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.DeviceFlowEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        Assert.True(doc.RootElement.TryGetProperty("device_authorization_endpoint", out var devEp));
        Assert.Contains("/connect/device_authorization", devEp.GetString());

        var grants = doc.RootElement.GetProperty("grant_types_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("urn:ietf:params:oauth:grant-type:device_code", grants);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CIBA — poll mode (OpenID CIBA Core 1.0)
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Ciba_BackchannelAuth_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // CibaEnabled = false

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("ciba-client", "ciba-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("scope", "openid"),
                new("login_hint", "alice"),
            ]),
        });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Ciba_BackchannelAuth_IssuesAuthReqId_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.CibaEnabled = true);

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("ciba-client", "ciba-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("scope", "openid profile"),
                new("login_hint", "alice"),
            ]),
        });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("auth_req_id", out var ari) && !string.IsNullOrEmpty(ari.GetString()));
        Assert.Equal(120, body.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal(5, body.RootElement.GetProperty("interval").GetInt32());
    }

    [Fact]
    public async Task Ciba_BackchannelAuth_Returns400_NoHint()
    {
        await using var app = TestWebApp.Create(opts => opts.CibaEnabled = true);

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("ciba-client", "ciba-secret")) },
            Content = new FormUrlEncodedContent([new("scope", "openid")]),
        });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Ciba_Token_Returns400_AuthorizationPending_BeforeApproval()
    {
        await using var app = TestWebApp.Create(opts => opts.CibaEnabled = true);

        var authResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("ciba-client", "ciba-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("scope", "openid"),
                new("login_hint", "alice"),
            ]),
        });
        var authBody = JsonDocument.Parse(await authResp.Content.ReadAsStringAsync());
        var authReqId = authBody.RootElement.GetProperty("auth_req_id").GetString()!;

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("ciba-client", "ciba-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "urn:ietf:params:oauth:grant-type:ciba"),
                new("auth_req_id", authReqId),
            ]),
        });

        Assert.Equal(HttpStatusCode.BadRequest, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.Equal("authorization_pending", tokenBody.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Ciba_Token_IssuesTokens_AfterOutOfBandApproval()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.CibaEnabled = true;
            opts.CibaPollingIntervalSeconds = 0;
        });

        var authResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("ciba-client", "ciba-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("scope", "openid profile"),
                new("login_hint", "alice"),
            ]),
        });
        var authBody = JsonDocument.Parse(await authResp.Content.ReadAsStringAsync());
        var authReqId = authBody.RootElement.GetProperty("auth_req_id").GetString()!;

        // Simulate out-of-band approval by directly updating the stored request
        var cibaStore = app.Services.GetRequiredService<IAdapter<BackchannelAuthenticationRequest>>();
        var stored = await cibaStore.FindAsync(authReqId);
        Assert.NotNull(stored);
        stored.Subject = "alice";
        stored.GrantedScopes = ["openid", "profile"];
        stored.Status = BackchannelAuthenticationStatus.Approved;
        await cibaStore.StoreAsync(authReqId, stored, stored.ExpiresAt - DateTimeOffset.UtcNow);

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("ciba-client", "ciba-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "urn:ietf:params:oauth:grant-type:ciba"),
                new("auth_req_id", authReqId),
            ]),
        });

        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.True(tokenBody.RootElement.TryGetProperty("access_token", out _));
        Assert.True(tokenBody.RootElement.TryGetProperty("id_token", out _));
    }

    [Fact]
    public async Task Ciba_Discovery_AdvertisesEndpoint_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.CibaEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        Assert.True(doc.RootElement.TryGetProperty("backchannel_authentication_endpoint", out var cibaEp));
        Assert.Contains("/connect/ciba", cibaEp.GetString());

        var grants = doc.RootElement.GetProperty("grant_types_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("urn:ietf:params:oauth:grant-type:ciba", grants);

        var modes = doc.RootElement.GetProperty("backchannel_token_delivery_modes_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("poll", modes);
    }
}
