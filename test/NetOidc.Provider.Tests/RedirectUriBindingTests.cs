using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P2.3 (redirect_uri at the token endpoint).</summary>
public sealed class RedirectUriBindingTests
{
    private const string Callback = "https://client.test.example.com/callback";

    [Fact]
    public async Task RedirectUriSentInAuthorization_MustBeRepeated()
    {
        await using var app = TestWebApp.Create();
        var code = await AuthorizeAsync(app, includeRedirectUri: true);

        var resp = await RedeemAsync(app, code, redirectUri: null);

        await AssertInvalidGrantAsync(resp);
    }

    [Fact]
    public async Task RedirectUriSentInAuthorization_MustMatchExactly()
    {
        await using var app = TestWebApp.Create();
        var code = await AuthorizeAsync(app, includeRedirectUri: true);

        var resp = await RedeemAsync(app, code, redirectUri: Callback + "/");

        await AssertInvalidGrantAsync(resp);
    }

    [Fact]
    public async Task RedirectUriSentInAuthorization_Repeated_Succeeds()
    {
        await using var app = TestWebApp.Create();
        var code = await AuthorizeAsync(app, includeRedirectUri: true);

        var resp = await RedeemAsync(app, code, redirectUri: Callback);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task RedirectUriOmittedInAuthorization_MayBeOmitted()
    {
        await using var app = TestWebApp.Create();
        var code = await AuthorizeAsync(app, includeRedirectUri: false);

        var resp = await RedeemAsync(app, code, redirectUri: null);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private static async Task<string> AuthorizeAsync(TestWebApp app, bool includeRedirectUri)
    {
        await app.Client.PostAsync("/test/signin", new FormUrlEncodedContent([new("subject", "alice")]));
        var url = "/connect/authorize?client_id=test-client&response_type=code&scope=openid";
        if (includeRedirectUri) url += "&redirect_uri=" + Uri.EscapeDataString(Callback);
        var resp = await app.Client.GetAsync(url);
        return HttpUtility.ParseQueryString(resp.Headers.Location!.Query)["code"]!;
    }

    private static Task<HttpResponseMessage> RedeemAsync(TestWebApp app, string code, string? redirectUri)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
        };
        if (redirectUri is not null) form.Add(new("redirect_uri", redirectUri));
        return app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret"))) },
            Content = new FormUrlEncodedContent(form),
        });
    }

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.BadRequest, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal("invalid_grant", JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }
}
