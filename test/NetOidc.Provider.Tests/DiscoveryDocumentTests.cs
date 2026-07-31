using System.Text.Json;

namespace NetOidc.Provider.Tests;

public sealed class DiscoveryDocumentTests
{
    [Fact]
    public async Task DiscoveryEndpoint_Returns200WithIssuer()
    {
        await using var app = TestWebApp.Create();

        var response = await app.Client.GetAsync("/.well-known/openid-configuration");

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);

        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "https://auth.test.example.com",
            json.RootElement.GetProperty("issuer").GetString());
    }

    [Fact]
    public async Task DiscoveryEndpoint_ContainsRequiredEndpoints()
    {
        await using var app = TestWebApp.Create();

        var json = JsonDocument.Parse(
            await app.Client.GetStringAsync("/.well-known/openid-configuration"));

        var root = json.RootElement;
        Assert.Contains("/connect/authorize",
            root.GetProperty("authorization_endpoint").GetString());
        Assert.Contains("/connect/token",
            root.GetProperty("token_endpoint").GetString());
        Assert.Contains("/connect/userinfo",
            root.GetProperty("userinfo_endpoint").GetString());
        Assert.Contains("/.well-known/jwks.json",
            root.GetProperty("jwks_uri").GetString());
    }

    [Fact]
    public async Task JwksEndpoint_ReturnsRsaPublicKey()
    {
        await using var app = TestWebApp.Create();

        var json = JsonDocument.Parse(
            await app.Client.GetStringAsync("/.well-known/jwks.json"));

        var keys = json.RootElement.GetProperty("keys");
        // JWKS now contains a signing key (use=sig) and an encryption key (use=enc)
        Assert.True(keys.GetArrayLength() >= 1);

        var key = keys[0];
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.True(key.TryGetProperty("n", out _));
        Assert.True(key.TryGetProperty("e", out _));
        // Private key MUST NOT be present
        Assert.False(key.TryGetProperty("d", out _));
    }
}
