using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Adapters;
using NetOidc.Provider.Dcr;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P2.6 (CSRF and user-code guessing on device approval)
/// and P2.7 (resource exhaustion: sweeping and per-IP budgets).
/// </summary>
public sealed class AbuseProtectionTests
{
    // ── P2.6 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DeviceApproval_WithoutAntiforgeryToken_IsRejected()
    {
        await using var app = CreateDeviceApp();
        var userCode = await StartDeviceFlowAsync(app);
        await SignInAsync(app, "alice");

        var resp = await app.Client.PostAsync("/connect/device", new FormUrlEncodedContent(
            [new("user_code", userCode), new("action", "approve")]));

        await AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task DeviceApproval_WithTokenIssuedBeforeSignIn_IsRejected()
    {
        await using var app = CreateDeviceApp();
        var userCode = await StartDeviceFlowAsync(app);

        // Token obtained anonymously is bound to the anonymous identity.
        var prompt = JsonDocument.Parse(await app.Client.GetStringAsync("/connect/device"));
        var csrf = prompt.RootElement.GetProperty("csrf");
        await SignInAsync(app, "alice");

        var resp = await app.Client.PostAsync("/connect/device", new FormUrlEncodedContent(
        [
            new("user_code", userCode),
            new("action", "approve"),
            new(csrf.GetProperty("field_name").GetString()!, csrf.GetProperty("token").GetString()!),
        ]));

        await AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task DeviceApproval_WithAntiforgeryToken_Succeeds()
    {
        await using var app = CreateDeviceApp();
        var userCode = await StartDeviceFlowAsync(app);
        await SignInAsync(app, "alice");

        var resp = await Phase6Tests.DeviceDecisionAsync(app.Client, userCode, "approve");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task RepeatedWrongUserCodes_LockOutFurtherAttempts()
    {
        await using var app = CreateDeviceApp(o => o.DeviceUserCodeMaxFailedAttempts = 3);
        var realCode = await StartDeviceFlowAsync(app);
        await SignInAsync(app, "alice");

        for (var i = 0; i < 3; i++)
            await AssertErrorAsync(await Phase6Tests.DeviceDecisionAsync(app.Client, "WRONG-CODE", "approve"),
                HttpStatusCode.BadRequest, "invalid_grant");

        // Even the correct code is refused once the budget is exhausted.
        var blocked = await Phase6Tests.DeviceDecisionAsync(app.Client, realCode, "approve");
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.NotNull(blocked.Headers.RetryAfter);
    }

    // ── P2.7 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NonceEndpoint_IsBudgetedPerIp()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.VciEnabled = true;
            o.UnauthenticatedRequestsPerMinute = 3;
        });

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.OK, (await NonceAsync(app, "198.51.100.1")).StatusCode);

        var limited = await NonceAsync(app, "198.51.100.1");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);

        // Another caller has its own budget.
        Assert.Equal(HttpStatusCode.OK, (await NonceAsync(app, "198.51.100.2")).StatusCode);
    }

    [Fact]
    public async Task Registration_IsBudgetedPerIp()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DcrEnabled = true;
            o.UnauthenticatedRequestsPerMinute = 2;
        });
        var req = new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] };

        Assert.Equal(HttpStatusCode.Created, (await app.Client.PostAsJsonAsync("/connect/register", req)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await app.Client.PostAsJsonAsync("/connect/register", req)).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await app.Client.PostAsJsonAsync("/connect/register", req)).StatusCode);
    }

    [Fact]
    public async Task InMemoryAdapter_SweepsExpiredEntries()
    {
        var adapter = new InMemoryAdapter<Grant>();
        for (var i = 0; i < 100; i++)
            await adapter.StoreAsync($"old-{i}", new Grant { GrantId = "g", ClientId = "c", Subject = "s" },
                TimeSpan.FromMilliseconds(-1));
        await adapter.StoreAsync("live", new Grant { GrantId = "g", ClientId = "c", Subject = "s" },
            TimeSpan.FromHours(1));

        adapter.Sweep(DateTimeOffset.UtcNow);

        Assert.Equal(1, adapter.Count);
        Assert.NotNull(await adapter.FindAsync("live"));
    }

    [Fact]
    public async Task ReplayCache_SweepsExpiredEntries_AndStillDetectsLiveReplays()
    {
        var cache = new InMemoryReplayCache();
        for (var i = 0; i < 100; i++)
            await cache.TryAddAsync($"old-{i}", DateTimeOffset.UtcNow.AddSeconds(-1));
        Assert.True(await cache.TryAddAsync("live", DateTimeOffset.UtcNow.AddMinutes(5)));

        cache.Sweep(DateTimeOffset.UtcNow);

        Assert.Equal(1, cache.Count);
        Assert.False(await cache.TryAddAsync("live", DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static TestWebApp CreateDeviceApp(Action<Configuration.ProviderOptions>? configure = null) =>
        TestWebApp.Create(o =>
        {
            o.DeviceFlowEnabled = true;
            configure?.Invoke(o);
        });

    private static async Task<string> StartDeviceFlowAsync(TestWebApp app)
    {
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("device-client:device-secret"))) },
            Content = new FormUrlEncodedContent([new("scope", "openid")]),
        });
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("user_code").GetString()!;
    }

    private static Task SignInAsync(TestWebApp app, string subject) =>
        app.Client.PostAsync("/test/signin", new FormUrlEncodedContent([new("subject", subject)]));

    private static Task<HttpResponseMessage> NonceAsync(TestWebApp app, string ip)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/nonce");
        req.Headers.Add("X-Test-Remote-Ip", ip);
        return app.Client.SendAsync(req);
    }

    private static async Task AssertErrorAsync(HttpResponseMessage resp, HttpStatusCode status, string error)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == status, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal(error, JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }
}
