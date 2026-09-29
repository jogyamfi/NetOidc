using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Tests;

/// <summary>Shared helpers for driving the provider over HTTP in tests.</summary>
internal static class Oidc
{
    public const string Callback = "https://client.test.example.com/callback";

    /// <summary>A fixed PKCE verifier and its S256 challenge.</summary>
    public static readonly string Verifier = new('v', 43);
    public static readonly string Challenge =
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));

    public static async Task SignInAsync(TestWebApp app, string subject, DateTimeOffset? authTime = null, string? acr = null)
    {
        var form = new List<KeyValuePair<string, string>> { new("subject", subject) };
        if (authTime is not null) form.Add(new("auth_time", authTime.Value.ToUnixTimeSeconds().ToString()));
        if (acr is not null) form.Add(new("acr", acr));
        var resp = await app.Client.PostAsync("/test/signin", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    /// <summary>GETs the authorization endpoint with the given query parameters.</summary>
    public static Task<HttpResponseMessage> AuthorizeAsync(TestWebApp app, params (string Key, string Value)[] query) =>
        app.Client.GetAsync("/connect/authorize?" +
            string.Join('&', query.Select(q => $"{q.Key}={Uri.EscapeDataString(q.Value)}")));

    /// <summary>Parameters from the query or fragment of a redirect.</summary>
    public static System.Collections.Specialized.NameValueCollection ResponseParams(HttpResponseMessage resp)
    {
        var location = resp.Headers.Location ?? throw new InvalidOperationException($"no redirect ({(int)resp.StatusCode})");
        var uri = location.IsAbsoluteUri ? location : new Uri(new Uri("https://op.test"), location);
        var part = !string.IsNullOrEmpty(uri.Fragment) ? uri.Fragment.TrimStart('#') : uri.Query.TrimStart('?');
        return HttpUtility.ParseQueryString(part);
    }

    public static AuthenticationHeaderValue Basic(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    /// <summary>POSTs to the token endpoint, optionally with Basic client authentication.</summary>
    public static Task<HttpResponseMessage> TokenAsync(
        TestWebApp app, List<KeyValuePair<string, string>> form, (string Id, string Secret)? basic = null,
        string? dpop = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token") { Content = new FormUrlEncodedContent(form) };
        if (basic is { } b) req.Headers.Authorization = Basic(b.Id, b.Secret);
        if (dpop is not null) req.Headers.Add("DPoP", dpop);
        return app.Client.SendAsync(req);
    }

    /// <summary>Signs in, authorizes test-client for a code, and redeems it.</summary>
    public static async Task<JsonElement> CodeFlowAsync(
        TestWebApp app, string subject = "alice", string scope = "openid",
        string clientId = "test-client", string secret = "test-secret", params (string, string)[] extra)
    {
        await SignInAsync(app, subject);
        var query = new List<(string, string)>
        {
            ("client_id", clientId), ("response_type", "code"), ("scope", scope), ("redirect_uri", Callback),
        };
        query.AddRange(extra);
        var authz = await AuthorizeAsync(app, [.. query]);
        var code = ResponseParams(authz)["code"] ?? throw new InvalidOperationException(authz.Headers.Location?.ToString());
        var token = await TokenAsync(app,
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", Callback),
        ], (clientId, secret));
        var body = await token.Content.ReadAsStringAsync();
        Assert.True(token.StatusCode == HttpStatusCode.OK, body);
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    public static JsonWebToken Jwt(string token) => new(token);

    public static async Task AssertErrorAsync(HttpResponseMessage resp, HttpStatusCode status, string error)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == status, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal(error, JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }

    /// <summary>Asserts an authorization error returned by redirect.</summary>
    public static void AssertRedirectError(HttpResponseMessage resp, string error)
    {
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal(error, ResponseParams(resp)["error"]);
    }
}
