using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P1.9 (introspection authorisation and response).</summary>
public sealed class IntrospectionSecurityTests
{
    [Fact]
    public async Task OtherClient_CannotIntrospectToken()
    {
        await using var app = TestWebApp.Create();
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "openid");

        using var doc = await IntrospectAsync(app, token, "cc-client", "cc-secret");

        Assert.False(doc.RootElement.GetProperty("active").GetBoolean());
        Assert.False(doc.RootElement.TryGetProperty("sub", out _));
    }

    [Fact]
    public async Task Owner_CanIntrospectToken()
    {
        await using var app = TestWebApp.Create();
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "openid");

        using var doc = await IntrospectAsync(app, token, "test-client", "test-secret");

        Assert.True(doc.RootElement.GetProperty("active").GetBoolean());
        Assert.Equal("alice", doc.RootElement.GetProperty("sub").GetString());
        Assert.Equal("test-client", doc.RootElement.GetProperty("client_id").GetString());
        Assert.Equal("Bearer", doc.RootElement.GetProperty("token_type").GetString());
        var iat = doc.RootElement.GetProperty("iat").GetInt64();
        Assert.InRange(iat, DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(),
            DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds());
    }

    [Fact]
    public async Task ResourceServer_AuthorisedByPolicy_CanIntrospect()
    {
        await using var app = TestWebApp.Create(o =>
            o.AuthorizeIntrospection = (ctx, _) => Task.FromResult(ctx.CallerClientId == "cc-client"));
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "openid");

        using var doc = await IntrospectAsync(app, token, "cc-client", "cc-secret");

        Assert.True(doc.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task DPoPBoundToken_ReportsTokenTypeAndCnf()
    {
        await using var app = TestWebApp.Create();
        var factory = app.Services.GetRequiredService<TokenFactory>();
        const string jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
        await app.Services.GetRequiredService<IAdapter<AccessToken>>().StoreAsync("dpop-jti", new AccessToken
        {
            TokenId = "dpop-jti",
            GrantId = "dpop-jti",
            ClientId = "test-client",
            Subject = "alice",
            Scopes = ["openid"],
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            CnfJwkThumbprint = jkt,
        }, TimeSpan.FromHours(1));
        var token = factory.CreateAccessToken("dpop-jti", "alice", "test-client", ["openid"], cnfJwkThumbprint: jkt);

        using var doc = await IntrospectAsync(app, token, "test-client", "test-secret");

        Assert.Equal("DPoP", doc.RootElement.GetProperty("token_type").GetString());
        Assert.Equal(jkt, doc.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
    }

    private static async Task<JsonDocument> IntrospectAsync(TestWebApp app, string token, string id, string secret)
    {
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"))) },
            Content = new FormUrlEncodedContent([new("token", token)]),
        });
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
    }
}
