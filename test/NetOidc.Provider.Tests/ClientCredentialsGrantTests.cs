using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Tests;

public sealed class ClientCredentialsGrantTests
{
    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    [Fact]
    public async Task ClientCredentials_ReturnsAccessToken()
    {
        await using var app = TestWebApp.Create();

        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        request.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret"));
        request.Content = new FormUrlEncodedContent([
            new("grant_type", "client_credentials"),
            new("scope", "profile"),
        ]);

        var resp = await app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(body.TryGetProperty("access_token", out _));
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.True(body.TryGetProperty("expires_in", out _));
        Assert.False(body.TryGetProperty("refresh_token", out _));
        Assert.False(body.TryGetProperty("id_token", out _));
    }

    [Fact]
    public async Task ClientCredentials_DefaultsToAllAllowedScopes_WhenScopeOmitted()
    {
        await using var app = TestWebApp.Create();

        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        request.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret"));
        request.Content = new FormUrlEncodedContent([
            new("grant_type", "client_credentials"),
        ]);

        var resp = await app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ClientCredentials_ReturnsError_ForDisallowedScope()
    {
        await using var app = TestWebApp.Create();

        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        request.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret"));
        request.Content = new FormUrlEncodedContent([
            new("grant_type", "client_credentials"),
            new("scope", "openid"),   // not in cc-client.AllowedScopes
        ]);

        var resp = await app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("invalid_scope", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task ClientCredentials_ReturnsError_WhenGrantTypeNotAllowed()
    {
        await using var app = TestWebApp.Create();

        // test-client only allows authorization_code
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        request.Headers.Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret"));
        request.Content = new FormUrlEncodedContent([
            new("grant_type", "client_credentials"),
        ]);

        var resp = await app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("unauthorized_client", body.GetProperty("error").GetString());
    }
}
