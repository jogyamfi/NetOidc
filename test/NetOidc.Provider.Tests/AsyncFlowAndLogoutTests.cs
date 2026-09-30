using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Ciba;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Logout;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P3.14 (CIBA), P3.15 (device flow) and P3.16 (logout).
/// Outbound calls (CIBA notifications, logout tokens) are captured by <see cref="Recorder"/>.
/// </summary>
public sealed class AsyncFlowAndLogoutTests
{
    /// <summary>Captures outbound HTTP requests made by the provider.</summary>
    private sealed class Recorder : HttpMessageHandler
    {
        public ConcurrentQueue<(Uri Uri, string? Authorization, string Body)> Requests { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(ct);
            Requests.Enqueue((request.RequestUri!, request.Headers.Authorization?.ToString(), body));
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }
    }

    private static TestWebApp CreateApp(Recorder recorder, Action<ProviderOptions> configure) =>
        TestWebApp.Create(configure, builder =>
            builder.Services.AddHttpClient(BackChannelLogoutService.TrustedHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => recorder));

    // ── P3.14 CIBA ──────────────────────────────────────────────────────────

    private static Client CibaClient(string mode) => new()
    {
        ClientId = $"ciba-{mode}",
        ClientSecret = "secret",
        AllowedGrantTypes = ["urn:openid:params:grant-type:ciba", "refresh_token"],
        AllowedScopes = ["openid", "profile"],
        CibaDeliveryMode = mode,
        CibaClientNotificationEndpoint = "https://rp.example.com/ciba/notify",
    };

    private static TestWebApp CreateCibaApp(Recorder recorder, Func<BackchannelAuthenticationRequest, CancellationToken, Task>? hook = null) =>
        CreateApp(recorder, o =>
        {
            o.CibaEnabled = true;
            o.CibaPollingIntervalSeconds = 0;
            o.ProcessBackchannelAuthenticationRequest = hook ?? ((_, _) => Task.CompletedTask);
            o.StaticClients = [.. o.StaticClients, CibaClient("poll"), CibaClient("ping"), CibaClient("push")];
        });

    private static async Task<HttpResponseMessage> StartCibaAsync(
        TestWebApp app, string clientId, params (string, string)[] extra)
    {
        var form = new List<KeyValuePair<string, string>> { new("scope", "openid"), new("login_hint", "alice") };
        form.AddRange(extra.Select(e => new KeyValuePair<string, string>(e.Item1, e.Item2)));
        return await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = Oidc.Basic(clientId, "secret") },
            Content = new FormUrlEncodedContent(form),
        });
    }

    private static async Task<string> AuthReqIdAsync(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.OK, body);
        return JsonDocument.Parse(body).RootElement.GetProperty("auth_req_id").GetString()!;
    }

    private static Task<HttpResponseMessage> PollAsync(TestWebApp app, string clientId, string authReqId) =>
        Oidc.TokenAsync(app,
            [new("grant_type", "urn:openid:params:grant-type:ciba"), new("auth_req_id", authReqId)],
            (clientId, "secret"));

    [Fact]
    public async Task Ciba_Poll_CompletedByHost_IssuesTokens()
    {
        var recorder = new Recorder();
        await using var app = CreateCibaApp(recorder);
        var id = await AuthReqIdAsync(await StartCibaAsync(app, "ciba-poll"));

        await Oidc.AssertErrorAsync(await PollAsync(app, "ciba-poll", id), HttpStatusCode.BadRequest, "authorization_pending");
        Assert.True(await app.Services.GetRequiredService<ICibaService>().CompleteAsync(id, approve: true, subject: "alice", acr: "urn:acr:mfa"));

        var token = await PollAsync(app, "ciba-poll", id);
        var idToken = Oidc.Jwt(JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("id_token").GetString()!);
        Assert.Equal("alice", idToken.Subject);
        Assert.Equal("urn:acr:mfa", idToken.GetClaim("acr").Value);
    }

    [Fact]
    public async Task Ciba_Ping_NotifiesTheClient()
    {
        var recorder = new Recorder();
        await using var app = CreateCibaApp(recorder);
        var id = await AuthReqIdAsync(await StartCibaAsync(app, "ciba-ping", ("client_notification_token", "ntok")));

        await app.Services.GetRequiredService<ICibaService>().CompleteAsync(id, approve: true, subject: "alice");

        var (uri, auth, body) = Assert.Single(recorder.Requests);
        Assert.Equal("https://rp.example.com/ciba/notify", uri.ToString());
        Assert.Equal("Bearer ntok", auth);
        Assert.Equal(id, JsonDocument.Parse(body).RootElement.GetProperty("auth_req_id").GetString());
        Assert.Equal(HttpStatusCode.OK, (await PollAsync(app, "ciba-ping", id)).StatusCode);
    }

    [Fact]
    public async Task Ciba_Push_DeliversTokensWithAuthReqIdAndHashes()
    {
        var recorder = new Recorder();
        await using var app = CreateCibaApp(recorder);
        var start = await StartCibaAsync(app, "ciba-push", ("client_notification_token", "ntok"));
        Assert.False(JsonDocument.Parse(await start.Content.ReadAsStringAsync()).RootElement.TryGetProperty("interval", out _));
        var id = await AuthReqIdAsync(start);

        await app.Services.GetRequiredService<ICibaService>().CompleteAsync(id, approve: true, subject: "alice");

        var (_, auth, body) = Assert.Single(recorder.Requests);
        Assert.Equal("Bearer ntok", auth);
        var payload = JsonDocument.Parse(body).RootElement;
        var idToken = Oidc.Jwt(payload.GetProperty("id_token").GetString()!);
        Assert.Equal(id, idToken.GetClaim("urn:openid:params:jwt:claim:auth_req_id").Value);
        Assert.True(idToken.TryGetClaim("at_hash", out _));
        Assert.True(idToken.TryGetClaim("rt_hash", out _));

        // Push clients do not poll.
        await Oidc.AssertErrorAsync(await PollAsync(app, "ciba-push", id), HttpStatusCode.BadRequest, "unauthorized_client");
    }

    [Fact]
    public async Task Ciba_Validation()
    {
        var recorder = new Recorder();
        await using var app = CreateCibaApp(recorder);

        await Oidc.AssertErrorAsync(await StartCibaAsync(app, "ciba-ping"), HttpStatusCode.BadRequest, "invalid_request");
        await Oidc.AssertErrorAsync(await StartCibaAsync(app, "ciba-poll", ("binding_message", new string('x', 65))),
            HttpStatusCode.BadRequest, "invalid_binding_message");
        await Oidc.AssertErrorAsync(await StartCibaAsync(app, "ciba-poll", ("requested_expiry", "0")),
            HttpStatusCode.BadRequest, "invalid_request");

        var withExpiry = await StartCibaAsync(app, "ciba-poll", ("requested_expiry", "30"));
        Assert.Equal(30, JsonDocument.Parse(await withExpiry.Content.ReadAsStringAsync()).RootElement.GetProperty("expires_in").GetInt32());
    }

    [Fact]
    public async Task Ciba_HookRunsAfterTheRequestHasEnded()
    {
        var recorder = new Recorder();
        var ran = new TaskCompletionSource<bool>();
        await using var app = CreateCibaApp(recorder, async (_, ct) =>
        {
            await Task.Delay(200, ct);   // would throw if tied to the finished request
            ran.TrySetResult(!ct.IsCancellationRequested);
        });

        await AuthReqIdAsync(await StartCibaAsync(app, "ciba-poll"));

        Assert.True(await ran.Task.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    // ── P3.15 Device flow ───────────────────────────────────────────────────

    [Fact]
    public async Task Device_SlowDown_IncreasesTheInterval()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DeviceFlowEnabled = true;
            o.DevicePollingIntervalSeconds = 5;
        });
        var start = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = Oidc.Basic("device-client", "device-secret") },
            Content = new FormUrlEncodedContent([new("scope", "openid")]),
        });
        var deviceCode = JsonDocument.Parse(await start.Content.ReadAsStringAsync()).RootElement.GetProperty("device_code").GetString()!;

        Task<HttpResponseMessage> Poll() => Oidc.TokenAsync(app,
            [new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), new("device_code", deviceCode)],
            ("device-client", "device-secret"));

        await Oidc.AssertErrorAsync(await Poll(), HttpStatusCode.BadRequest, "authorization_pending");
        var slow = await Poll();
        await Oidc.AssertErrorAsync(slow, HttpStatusCode.BadRequest, "slow_down");
        Assert.Contains("10 seconds", await slow.Content.ReadAsStringAsync());
        var slower = await Poll();
        Assert.Contains("15 seconds", await slower.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Device_UnknownScope_IsRejected()
    {
        await using var app = TestWebApp.Create(o => o.DeviceFlowEnabled = true);
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = Oidc.Basic("device-client", "device-secret") },
            Content = new FormUrlEncodedContent([new("scope", "openid admin")]),
        });
        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_scope");
    }

    // ── P3.16 Logout ────────────────────────────────────────────────────────

    private static Client LogoutClient(string id) => new()
    {
        ClientId = id,
        ClientSecret = "secret",
        AllowedGrantTypes = ["authorization_code"],
        AllowedScopes = ["openid"],
        // Distinct hosts put each client in its own pairwise sector.
        RedirectUris = [$"https://{id}.example.com/cb"],
        RequirePkce = false,
        RequireConsent = false,
        BackChannelLogoutUri = $"https://{id}.example.com/bc-logout",
        BackChannelLogoutSessionRequired = true,
        FrontChannelLogoutUri = $"https://{id}.example.com/fc-logout",
        FrontChannelLogoutSessionRequired = true,
    };

    private static TestWebApp CreateLogoutApp(Recorder recorder, bool pairwise = false) =>
        CreateApp(recorder, o =>
        {
            o.LogoutEnabled = true;
            o.BackChannelLogoutEnabled = true;
            o.FrontChannelLogoutEnabled = true;
            if (pairwise)
            {
                o.SubjectType = "pairwise";
                o.PairwiseSalt = "a-secret-pairwise-salt-of-32-bytes!!";
            }
            o.StaticClients =
            [
                .. o.StaticClients,
                LogoutClient("rp1"),
                LogoutClient("rp2"),
            ];
        });

    private static async Task<string> SignInToAsync(TestWebApp app, string clientId)
    {
        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", clientId), ("response_type", "code"), ("scope", "openid"), ("redirect_uri", $"https://{clientId}.example.com/cb"));
        var token = await Oidc.TokenAsync(app,
        [
            new("grant_type", "authorization_code"), new("code", Oidc.ResponseParams(resp)["code"]!),
            new("redirect_uri", $"https://{clientId}.example.com/cb"),
        ], (clientId, "secret"));
        return JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("id_token").GetString()!;
    }

    [Fact]
    public async Task Logout_SendsTypedLogoutTokens_WithEachClientsOwnSub_AndRendersFrontChannelFrames()
    {
        var recorder = new Recorder();
        await using var app = CreateLogoutApp(recorder, pairwise: true);
        await Oidc.SignInAsync(app, "alice");
        var rp1IdToken = await SignInToAsync(app, "rp1");
        var rp2IdToken = await SignInToAsync(app, "rp2");

        var resp = await app.Client.GetAsync("/connect/end_session?id_token_hint=" + rp1IdToken);

        // Back channel: one logout token per client, typed, with that client's pairwise sub.
        Assert.Equal(2, recorder.Requests.Count);
        foreach (var (uri, _, body) in recorder.Requests)
        {
            var logoutToken = Oidc.Jwt(HttpUtility.ParseQueryString(body)["logout_token"]!);
            Assert.Equal("logout+jwt", logoutToken.Typ);
            var expectedSub = uri.Host.StartsWith("rp1") ? Oidc.Jwt(rp1IdToken).Subject : Oidc.Jwt(rp2IdToken).Subject;
            Assert.Equal(expectedSub, logoutToken.Subject);
        }
        Assert.NotEqual(Oidc.Jwt(rp1IdToken).Subject, Oidc.Jwt(rp2IdToken).Subject);

        // Front channel: an iframe per client carrying iss and sid.
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("https://rp1.example.com/fc-logout?iss=", html);
        Assert.Contains("https://rp2.example.com/fc-logout?iss=", html);
        Assert.Contains("sid=" + Oidc.Jwt(rp1IdToken).GetClaim("sid").Value, html);
    }

    [Fact]
    public async Task ConfirmedLogout_WithoutHint_EndsTheCookieSession()
    {
        var recorder = new Recorder();
        await using var app = CreateLogoutApp(recorder);
        await Oidc.SignInAsync(app, "alice");
        await SignInToAsync(app, "rp1");

        var resp = await LogoutTests.ConfirmLogoutAsync(app, []);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);   // front-channel page
        Assert.Single(recorder.Requests);
    }
}
