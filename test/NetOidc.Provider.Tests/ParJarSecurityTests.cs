using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P1.7 (PAR must validate JAR request objects).</summary>
public sealed class ParJarSecurityTests : IDisposable
{
    private const string Callback = "https://client.test.example.com/callback";
    private readonly RSA _clientKey = RSA.Create(2048);

    public void Dispose() => _clientKey.Dispose();

    [Fact]
    public async Task TamperedRequestObject_IsRejectedAtPar()
    {
        await using var app = CreateApp();
        using var otherKey = RSA.Create(2048);

        var resp = await PushAsync(app, [new("request", RequestObject(otherKey, state: "s"))]);

        await AssertErrorAsync(resp, "invalid_request_object");
    }

    [Fact]
    public async Task UnsignedRequestObject_IsRejectedAtPar()
    {
        await using var app = CreateApp();
        var header = Base64UrlEncoder.Encode("""{"alg":"none"}""");
        var payload = Base64UrlEncoder.Encode(
            """{"iss":"jar-client","aud":"https://auth.test.example.com","response_type":"code"}""");

        var resp = await PushAsync(app, [new("request", $"{header}.{payload}.")]);

        await AssertErrorAsync(resp, "invalid_request_object");
    }

    [Fact]
    public async Task ValidRequestObject_OnlyItsParametersAreUsed()
    {
        await using var app = CreateApp();
        var push = await PushAsync(app,
        [
            new("request", RequestObject(_clientKey, state: "from-jwt")),
            new("state", "from-form"),   // must be ignored (RFC 9126 §3)
        ]);
        Assert.Equal(HttpStatusCode.Created, push.StatusCode);
        var requestUri = JsonDocument.Parse(await push.Content.ReadAsStringAsync())
            .RootElement.GetProperty("request_uri").GetString()!;

        await app.Client.PostAsync("/test/signin", new FormUrlEncodedContent([new("subject", "alice")]));
        var authz = await app.Client.GetAsync(
            $"/connect/authorize?client_id=jar-client&request_uri={Uri.EscapeDataString(requestUri)}");

        Assert.Equal(HttpStatusCode.Redirect, authz.StatusCode);
        var query = HttpUtility.ParseQueryString(authz.Headers.Location!.Query);
        Assert.Equal("from-jwt", query["state"]);
        Assert.NotNull(query["code"]);
    }

    [Fact]
    public async Task ClientAuthenticationParameters_AreNotPersisted()
    {
        await using var app = CreateApp();
        var push = await app.Client.PostAsync("/connect/par", new FormUrlEncodedContent(
        [
            new("client_id", "post-client"),
            new("client_secret", "post-secret-value"),
            new("response_type", "code"),
            new("redirect_uri", Callback),
            new("scope", "openid"),
        ]));
        Assert.Equal(HttpStatusCode.Created, push.StatusCode);
        var requestUri = JsonDocument.Parse(await push.Content.ReadAsStringAsync())
            .RootElement.GetProperty("request_uri").GetString()!;

        var stored = await app.Services.GetRequiredService<IAdapter<PushedAuthorizationRequest>>()
            .FindAsync(requestUri);

        Assert.DoesNotContain("post-secret-value", stored!.ParametersJson);
        Assert.DoesNotContain("client_secret", stored.ParametersJson);
    }

    [Fact]
    public async Task PushedRequestUri_IsRejected()
    {
        await using var app = CreateApp();

        var resp = await PushAsync(app,
        [
            new("response_type", "code"),
            new("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
        ], clientId: "par-client", secret: "par-secret");

        await AssertErrorAsync(resp, "invalid_request");
    }

    [Fact]
    public async Task DisallowedScope_IsRejectedAtPar()
    {
        await using var app = CreateApp();

        var resp = await PushAsync(app,
        [
            new("response_type", "code"),
            new("redirect_uri", Callback),
            new("scope", "openid admin"),
        ], clientId: "par-client", secret: "par-secret");

        await AssertErrorAsync(resp, "invalid_scope");
    }

    [Fact]
    public async Task ClientRequiringSignedRequest_CannotPushPlainParameters()
    {
        await using var app = CreateApp();

        var resp = await PushAsync(app,
        [
            new("response_type", "code"),
            new("redirect_uri", Callback),
        ]);

        await AssertErrorAsync(resp, "invalid_request");
    }

    [Fact]
    public void StructuredClaims_AreConvertedToJson()
    {
        using var doc = JsonDocument.Parse("""{"claims":{"id_token":{"email":null}},"state":"x","max_age":60}""");
        var claims = doc.RootElement.EnumerateObject()
            .ToDictionary(p => p.Name, p => (object)p.Value.Clone());

        var result = RequestObjectValidator.ToAuthorizationParameters(claims);

        Assert.Equal("x", result["state"]);
        Assert.Equal("60", result["max_age"]);
        using var parsed = JsonDocument.Parse(result["claims"]);
        Assert.True(parsed.RootElement.GetProperty("id_token").TryGetProperty("email", out _));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private TestWebApp CreateApp()
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new RsaSecurityKey(_clientKey.ExportParameters(false)) { KeyId = "jar" });
        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[] { new { kty = "RSA", use = "sig", kid = "jar", n = jwk.N, e = jwk.E } },
        });

        return TestWebApp.Create(o =>
        {
            o.PushedAuthorizationEnabled = true;
            o.JarEnabled = true;
            o.StaticClients =
            [
                .. o.StaticClients,
                new Client
                {
                    ClientId = "jar-client",
                    ClientSecret = "jar-secret",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = [Callback],
                    RequirePkce = false,
                    RequireSignedRequestObject = true,
                    JwksJson = jwks,
                },
                new Client
                {
                    ClientId = "post-client",
                    ClientSecret = "post-secret-value",
                    TokenEndpointAuthMethod = "client_secret_post",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    RedirectUris = [Callback],
                },
            ];
        });
    }

    private static string RequestObject(RSA key, string state) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "jar-client",
            Audience = "https://auth.test.example.com",
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["client_id"] = "jar-client",
                ["response_type"] = "code",
                ["redirect_uri"] = Callback,
                ["scope"] = "openid",
                ["state"] = state,
            },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(key) { KeyId = "jar" }, SecurityAlgorithms.RsaSha256),
        });

    private static Task<HttpResponseMessage> PushAsync(
        TestWebApp app, List<KeyValuePair<string, string>> form,
        string clientId = "jar-client", string secret = "jar-secret") =>
        app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/par")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{secret}"))) },
            Content = new FormUrlEncodedContent(form),
        });

    private static async Task AssertErrorAsync(HttpResponseMessage resp, string error)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.BadRequest, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal(error, JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }
}
