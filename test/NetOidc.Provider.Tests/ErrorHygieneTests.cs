using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Dcr;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P2.9 (no internal error details in responses).</summary>
public sealed class ErrorHygieneTests
{
    [Fact]
    public async Task DcrHookException_IsNotEchoed()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DcrEnabled = true;
            o.ValidateDynamicClient = (_, _) =>
                throw new InvalidOperationException("connection string Server=db;Password=hunter2");
        });

        var resp = await app.Client.PostAsJsonAsync("/connect/register",
            new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] });

        var body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.DoesNotContain("hunter2", body);
        Assert.Equal("invalid_client_metadata", JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task DcrHook_ClientMetadataValidationException_MessageIsReturned()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DcrEnabled = true;
            o.ValidateDynamicClient = (_, _) =>
                throw new ClientMetadataValidationException("client_name is required");
        });

        var resp = await app.Client.PostAsJsonAsync("/connect/register",
            new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] });

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_client_metadata", doc.RootElement.GetProperty("error").GetString());
        Assert.Equal("client_name is required", doc.RootElement.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task InvalidRequestObject_DoesNotLeakLibraryDiagnostics()
    {
        using var clientKey = RSA.Create(2048);
        using var wrongKey = RSA.Create(2048);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(clientKey.ExportParameters(false)));
        await using var app = TestWebApp.Create(o =>
        {
            o.JarEnabled = true;
            o.StaticClients =
            [
                .. o.StaticClients,
                new Client
                {
                    ClientId = "jar-client",
                    ClientSecret = "jar-secret",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    RequireConsent = false,
                    JwksJson = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", n = jwk.N, e = jwk.E } } }),
                },
            ];
        });
        var request = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "jar-client",
            Audience = "https://auth.test.example.com",
            Claims = new Dictionary<string, object> { ["response_type"] = "code" },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(wrongKey), SecurityAlgorithms.RsaSha256),
        });

        var resp = await app.Client.GetAsync($"/connect/authorize?client_id=jar-client&request={request}");

        var text = resp.Headers.Location is { } loc
            ? HttpUtility.UrlDecode(loc.ToString())
            : await resp.Content.ReadAsStringAsync();
        Assert.Contains("invalid_request", text);
        Assert.DoesNotContain("IDX", text);
    }

    [Fact]
    public async Task InvalidJwtBearerAssertion_DoesNotLeakLibraryDiagnostics()
    {
        using var clientKey = RSA.Create(2048);
        using var wrongKey = RSA.Create(2048);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(clientKey.ExportParameters(false)));
        await using var app = TestWebApp.Create(o =>
        {
            o.JwtBearerGrantEnabled = true;
            o.StaticClients =
            [
                .. o.StaticClients,
                new Client
                {
                    ClientId = "bearer-client",
                    ClientSecret = "bearer-secret",
                    AllowedGrantTypes = ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
                    AllowedScopes = ["profile"],
                    JwksJson = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", n = jwk.N, e = jwk.E } } }),
                },
            ];
        });
        var assertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "bearer-client",
            Audience = "https://auth.test.example.com",
            Subject = new ClaimsIdentity([new Claim("sub", "alice")]),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(wrongKey), SecurityAlgorithms.RsaSha256),
        });

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("bearer-client:bearer-secret"))) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new("assertion", assertion),
            ]),
        });

        var body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.DoesNotContain("IDX", body);
    }

    [Fact]
    public async Task MalformedAuthorizationDetails_DoesNotEchoParserDiagnostics()
    {
        await using var app = TestWebApp.Create(o => o.RichAuthorizationRequestsEnabled = true);
        await app.Client.PostAsync("/test/signin", new FormUrlEncodedContent([new("subject", "alice")]));

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code&scope=openid" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&authorization_details=" + Uri.EscapeDataString("[{\"type\": oops}]"));

        var description = HttpUtility.ParseQueryString(resp.Headers.Location!.Query)["error_description"];
        Assert.Equal("authorization_details is not valid JSON", description);
    }
}
