using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Tests;

/// <summary>
/// OpenID Connect Dynamic OP requirements found by the conformance suite (REMEDIATION_PLAN P6.2):
/// <c>request_uri</c> by reference (OIDC Core §6.2, §15.2) and relying-party key rotation through
/// <c>jwks_uri</c> (OIDC Core §10.1.1).
/// </summary>
public sealed class RequestUriAndKeyRotationTests
{
    private const string Issuer = "https://auth.test.example.com";
    private const string JwksUri = "https://rp.example.com/jwks.json";
    private const string RequestUri = "https://rp.example.com/request.jwt";

    private static TestWebApp CreateApp(FakeWeb web) => web.CreateApp(o =>
    {
        o.DcrEnabled = true;
        o.DcrAllowedGrantTypes = ["authorization_code", "client_credentials"];
        o.JarEnabled = true;
        o.RequestUriParameterSupported = true;
    });

    private static string Jwks(RSA key, string kid)
    {
        var p = key.ExportParameters(false);
        return JsonSerializer.Serialize(new
        {
            keys = new[] { new { kty = "RSA", use = "sig", kid, n = Base64UrlEncoder.Encode(p.Modulus!), e = Base64UrlEncoder.Encode(p.Exponent!) } },
        });
    }

    private static async Task<string> RegisterAsync(TestWebApp app, object metadata)
    {
        var resp = await app.Client.PostAsync("/connect/register",
            new StringContent(JsonSerializer.Serialize(metadata), Encoding.UTF8, "application/json"));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.Created, body);
        return JsonDocument.Parse(body).RootElement.GetProperty("client_id").GetString()!;
    }

    private static string Sign(RSA key, string kid, SecurityTokenDescriptor descriptor)
    {
        descriptor.SigningCredentials = new SigningCredentials(new RsaSecurityKey(key) { KeyId = kid }, SecurityAlgorithms.RsaSha256);
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    // ── request_uri ─────────────────────────────────────────────────────────

    [Fact]
    public async Task RegisteredRequestUri_IsFetchedAndUsed()
    {
        var web = new FakeWeb();
        using var key = RSA.Create(2048);
        await using var app = CreateApp(web);
        var discovery = JsonDocument.Parse(await app.Client.GetStringAsync("/.well-known/openid-configuration")).RootElement;
        Assert.True(discovery.GetProperty("request_uri_parameter_supported").GetBoolean());
        Assert.True(discovery.GetProperty("require_request_uri_registration").GetBoolean());

        var clientId = await RegisterAsync(app, new
        {
            redirect_uris = new[] { Oidc.Callback },
            jwks = JsonDocument.Parse(Jwks(key, "k1")).RootElement,
            request_uris = new[] { RequestUri + "#hash-of-contents" },
            require_pkce = false,
        });
        web.Serve(RequestUri, Sign(key, "k1", new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = Issuer,
            Claims = new Dictionary<string, object>
            {
                ["client_id"] = clientId, ["response_type"] = "code", ["scope"] = "openid",
                ["redirect_uri"] = Oidc.Callback, ["state"] = "from-request-uri",
            },
        }), "application/oauth-authz-req+jwt");
        await app.Services.GetRequiredService<Interaction.ConsentService>()
            .GrantAsync(clientId, "alice", ["openid"]);
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", clientId), ("response_type", "code"),
            ("scope", "openid"), ("request_uri", RequestUri + "#hash-of-contents"));

        var response = Oidc.ResponseParams(resp);
        Assert.NotNull(response["code"]);
        Assert.Equal("from-request-uri", response["state"]);
    }

    [Fact]
    public async Task UnregisteredRequestUri_IsNotFetched()
    {
        var web = new FakeWeb();
        using var key = RSA.Create(2048);
        await using var app = CreateApp(web);
        var clientId = await RegisterAsync(app, new
        {
            redirect_uris = new[] { Oidc.Callback },
            jwks = JsonDocument.Parse(Jwks(key, "k1")).RootElement,
            request_uris = new[] { RequestUri },
        });
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", clientId), ("response_type", "code"),
            ("scope", "openid"), ("redirect_uri", Oidc.Callback), ("request_uri", "https://attacker.example.com/r.jwt"));

        Oidc.AssertRedirectError(resp, "invalid_request_uri");
        Assert.DoesNotContain(web.Requests, u => u.Host == "attacker.example.com");
    }

    [Fact]
    public async Task RequestUri_IsRefusedWhenNotEnabled()
    {
        var web = new FakeWeb();
        await using var app = web.CreateApp(o => o.JarEnabled = true);
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"),
            ("scope", "openid"), ("redirect_uri", Oidc.Callback), ("request_uri", RequestUri));

        Oidc.AssertRedirectError(resp, "request_uri_not_supported");
        Assert.Empty(web.Requests);
    }

    // ── jwks_uri key rotation ───────────────────────────────────────────────

    [Fact]
    public async Task RotatedClientKeys_AreFetchedFromJwksUri()
    {
        var web = new FakeWeb();
        using var oldKey = RSA.Create(2048);
        using var newKey = RSA.Create(2048);
        web.Serve(JwksUri, Jwks(oldKey, "old"));
        await using var app = CreateApp(web);
        var clientId = await RegisterAsync(app, new
        {
            redirect_uris = new[] { Oidc.Callback },
            grant_types = new[] { "client_credentials" },
            response_types = Array.Empty<string>(),
            token_endpoint_auth_method = "private_key_jwt",
            jwks_uri = JwksUri,
        });

        Task<HttpResponseMessage> GrantAsync(RSA key, string kid) => app.Client.PostAsync("/connect/token",
            new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", Sign(key, kid, new SecurityTokenDescriptor
                {
                    Issuer = clientId,
                    Audience = Issuer + "/connect/token",
                    Subject = new ClaimsIdentity([new Claim("sub", clientId)]),
                    Expires = DateTime.UtcNow.AddMinutes(1),
                    Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString() },
                })),
            ]));

        Assert.Equal(HttpStatusCode.OK, (await GrantAsync(oldKey, "old")).StatusCode);

        // The RP publishes a new key and signs with it.
        web.Serve(JwksUri, Jwks(newKey, "new"));
        Assert.Equal(HttpStatusCode.OK, (await GrantAsync(newKey, "new")).StatusCode);

        // A key the RP never published is still refused, and the refresh is throttled.
        using var strangerKey = RSA.Create(2048);
        var fetches = web.Requests.Count(u => u.AbsoluteUri == JwksUri);
        Assert.Equal(HttpStatusCode.Unauthorized, (await GrantAsync(strangerKey, "stranger")).StatusCode);
        Assert.Equal(fetches, web.Requests.Count(u => u.AbsoluteUri == JwksUri));
    }
}
