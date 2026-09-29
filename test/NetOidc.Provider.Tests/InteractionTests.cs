using System.Net;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Interaction;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P3.2 (authorization POST) and P3.3 (prompt, max_age,
/// id_token_hint, login hints, consent and resuming suspended requests).
/// </summary>
public sealed class InteractionTests
{
    private static (string, string)[] CodeRequest(string clientId = "test-client", params (string, string)[] extra) =>
    [
        ("client_id", clientId), ("response_type", "code"), ("scope", "openid profile"),
        ("redirect_uri", Oidc.Callback), ("state", "st"), .. extra,
    ];

    [Fact]
    public async Task AuthorizationEndpoint_AcceptsPost()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await app.Client.PostAsync("/connect/authorize", new FormUrlEncodedContent(
            CodeRequest().Select(p => new KeyValuePair<string, string>(p.Item1, p.Item2))));

        Assert.NotNull(Oidc.ResponseParams(resp)["code"]);
    }

    [Fact]
    public async Task NotSignedIn_RedirectsToLogin_WithResumableReturnUrl_AndHints()
    {
        await using var app = TestWebApp.Create();

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest(extra: [("login_hint", "alice@example.com"), ("ui_locales", "fr")]));

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.StartsWith("/test/signin", location);
        var query = HttpUtility.ParseQueryString(new Uri(new Uri("https://op.test"), location).Query);
        Assert.Equal("alice@example.com", query["login_hint"]);
        Assert.Equal("fr", query["ui_locales"]);
        Assert.Contains("interaction=", query["returnUrl"]);

        // After signing in, following returnUrl completes the request.
        await Oidc.SignInAsync(app, "alice");
        var resumed = await app.Client.GetAsync(query["returnUrl"]);
        Assert.NotNull(Oidc.ResponseParams(resumed)["code"]);
        Assert.Equal("st", Oidc.ResponseParams(resumed)["state"]);
    }

    [Fact]
    public async Task PromptNone_NotSignedIn_ReturnsLoginRequired()
    {
        await using var app = TestWebApp.Create();

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest(extra: ("prompt", "none")));

        Oidc.AssertRedirectError(resp, "login_required");
        Assert.Equal("st", Oidc.ResponseParams(resp)["state"]);
    }

    [Fact]
    public async Task PromptNone_CombinedWithOtherValues_IsInvalid()
    {
        await using var app = TestWebApp.Create();
        var resp = await Oidc.AuthorizeAsync(app, CodeRequest(extra: ("prompt", "none login")));
        Oidc.AssertRedirectError(resp, "invalid_request");
    }

    [Fact]
    public async Task PromptLogin_ForcesLogin_ThenResumesAfterFreshLogin()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");
        await Task.Delay(1100);   // the existing login must predate the request

        var first = await Oidc.AuthorizeAsync(app, CodeRequest(extra: ("prompt", "login")));
        Assert.StartsWith("/test/signin", first.Headers.Location!.ToString());
        var returnUrl = HttpUtility.ParseQueryString(new Uri(new Uri("https://op.test"), first.Headers.Location).Query)["returnUrl"]!;

        // Resuming without logging in again is still refused.
        var notFresh = await app.Client.GetAsync(returnUrl);
        Assert.StartsWith("/test/signin", notFresh.Headers.Location!.ToString());

        await Task.Delay(1100);   // cookie IssuedUtc has one-second precision
        await Oidc.SignInAsync(app, "alice");
        var done = await app.Client.GetAsync(returnUrl);
        Assert.NotNull(Oidc.ResponseParams(done)["code"]);
    }

    [Fact]
    public async Task MaxAge_Exceeded_RequiresLogin()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice", authTime: DateTimeOffset.UtcNow.AddHours(-1));

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest(extra: [("max_age", "60"), ("prompt", "none")]));

        Oidc.AssertRedirectError(resp, "login_required");
    }

    [Fact]
    public async Task MaxAge_Satisfied_Completes()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice", authTime: DateTimeOffset.UtcNow.AddSeconds(-5));

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest(extra: ("max_age", "60")));

        Assert.NotNull(Oidc.ResponseParams(resp)["code"]);
    }

    [Fact]
    public async Task IdTokenHint_ForAnotherUser_WithPromptNone_ReturnsLoginRequired()
    {
        await using var app = TestWebApp.Create();
        var bobIdToken = (await Oidc.CodeFlowAsync(app, "bob")).GetProperty("id_token").GetString()!;
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest(extra: [("prompt", "none"), ("id_token_hint", bobIdToken)]));

        Oidc.AssertRedirectError(resp, "login_required");
    }

    [Fact]
    public async Task InvalidIdTokenHint_IsRejected()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest(extra: ("id_token_hint", "not.a.token")));

        Oidc.AssertRedirectError(resp, "invalid_request");
    }

    // ── Consent ──────────────────────────────────────────────────────────────

    private static TestWebApp CreateConsentApp() => TestWebApp.Create(o => o.StaticClients =
    [
        .. o.StaticClients,
        new Client
        {
            ClientId = "third-party",
            ClientSecret = "tp-secret",
            AllowedGrantTypes = ["authorization_code"],
            AllowedScopes = ["openid", "profile"],
            RedirectUris = [Oidc.Callback],
            RequirePkce = false,
            // RequireConsent defaults to true.
        },
    ]);

    [Fact]
    public async Task ConsentRequired_RedirectsToConsentPage_ThenCompletesAfterGrant()
    {
        await using var app = CreateConsentApp();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest("third-party"));
        var location = resp.Headers.Location!.ToString();
        Assert.StartsWith("/account/consent", location);
        var query = HttpUtility.ParseQueryString(new Uri(new Uri("https://op.test"), location).Query);
        Assert.Equal("third-party", query["client_id"]);
        Assert.Equal("openid profile", query["scope"]);

        // The host's consent page records the decision, then resumes the request.
        await app.Services.GetRequiredService<ConsentService>().GrantAsync("third-party", "alice", ["openid", "profile"]);
        var done = await app.Client.GetAsync(query["returnUrl"]);
        Assert.NotNull(Oidc.ResponseParams(done)["code"]);

        // Remembered: the next request completes directly.
        var again = await Oidc.AuthorizeAsync(app, CodeRequest("third-party"));
        Assert.NotNull(Oidc.ResponseParams(again)["code"]);
    }

    [Fact]
    public async Task PromptNone_WithoutConsent_ReturnsConsentRequired()
    {
        await using var app = CreateConsentApp();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest("third-party", ("prompt", "none")));

        Oidc.AssertRedirectError(resp, "consent_required");
    }

    [Fact]
    public async Task PromptConsent_AsksAgainEvenWhenConsented()
    {
        await using var app = CreateConsentApp();
        await Oidc.SignInAsync(app, "alice");
        await app.Services.GetRequiredService<ConsentService>().GrantAsync("third-party", "alice", ["openid", "profile"]);

        var resp = await Oidc.AuthorizeAsync(app, CodeRequest("third-party", ("prompt", "consent")));

        Assert.StartsWith("/account/consent", resp.Headers.Location!.ToString());
    }

    [Fact]
    public async Task PushedRequest_SurvivesTheLoginRedirect()
    {
        await using var app = TestWebApp.Create(o => o.PushedAuthorizationEnabled = true);
        var push = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/par")
        {
            Headers = { Authorization = Oidc.Basic("par-client", "par-secret") },
            Content = new FormUrlEncodedContent(
            [
                new("response_type", "code"), new("redirect_uri", Oidc.Callback), new("scope", "openid"),
            ]),
        });
        var requestUri = System.Text.Json.JsonDocument.Parse(await push.Content.ReadAsStringAsync())
            .RootElement.GetProperty("request_uri").GetString()!;

        var toLogin = await Oidc.AuthorizeAsync(app, ("client_id", "par-client"), ("request_uri", requestUri));
        var returnUrl = HttpUtility.ParseQueryString(new Uri(new Uri("https://op.test"), toLogin.Headers.Location!).Query)["returnUrl"]!;

        await Oidc.SignInAsync(app, "alice");
        var done = await app.Client.GetAsync(returnUrl);
        Assert.NotNull(Oidc.ResponseParams(done)["code"]);

        // …and is spent afterwards.
        var replay = await app.Client.GetAsync(returnUrl);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }
}
