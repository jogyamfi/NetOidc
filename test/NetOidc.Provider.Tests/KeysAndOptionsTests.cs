using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P4.1 (key management) and P4.4 (options validation).</summary>
public sealed class KeysAndOptionsTests
{
    /// <summary>A key store the test can change while the app runs (rotation).</summary>
    private sealed class MutableKeyStore : IKeyStore
    {
        public List<ProviderKey> Keys { get; } = [];
        public IReadOnlyList<ProviderKey> GetKeys() => Keys.ToList();
    }

    private static ProviderKey RsaKey(string kid, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null) => new()
    {
        Key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = kid },
        Algorithm = "RS256",
        NotBefore = notBefore,
        NotAfter = notAfter,
    };

    private static ProviderKey EncKey() => new()
    {
        Key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "enc" },
        Algorithm = "RSA-OAEP-256",
        Use = ProviderKeyUse.Encryption,
    };

    private static async Task<JsonElement> JwksAsync(TestWebApp app) =>
        JsonDocument.Parse(await app.Client.GetStringAsync("/.well-known/jwks.json")).RootElement.GetProperty("keys");

    // ── P4.1 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Rotation_PrePublishes_Switches_AndRetiresKeys()
    {
        var store = new MutableKeyStore();
        var oldKey = RsaKey("old");
        var newKey = RsaKey("new", notBefore: DateTimeOffset.UtcNow.AddDays(1));
        store.Keys.AddRange([oldKey, newKey, EncKey()]);
        await using var app = TestWebApp.Create(null, b => b.Services.AddSingleton<IKeyStore>(store));

        // Before activation: the successor is published but not used.
        var kids = (await JwksAsync(app)).EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToList();
        Assert.Contains("new", kids);
        var first = await Oidc.CodeFlowAsync(app);
        var oldToken = first.GetProperty("access_token").GetString()!;
        Assert.Equal("old", Oidc.Jwt(oldToken).Kid);

        // Activate the successor: new tokens use it, tokens signed by the old key still verify.
        store.Keys[1] = new ProviderKey { Key = newKey.Key, Algorithm = "RS256", NotBefore = DateTimeOffset.UtcNow.AddSeconds(-1) };
        var second = await Oidc.CodeFlowAsync(app, "bob");
        Assert.Equal("new", Oidc.Jwt(second.GetProperty("access_token").GetString()!).Kid);
        Assert.Equal(HttpStatusCode.OK, (await UserInfoAsync(app, oldToken)).StatusCode);

        // Retire the old key: it leaves the JWKS and its tokens stop verifying.
        store.Keys[0] = new ProviderKey { Key = oldKey.Key, Algorithm = "RS256", NotAfter = DateTimeOffset.UtcNow.AddSeconds(-1) };
        kids = (await JwksAsync(app)).EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToList();
        Assert.DoesNotContain("old", kids);
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(app, oldToken)).StatusCode);
    }

    [Fact]
    public async Task EcKey_SignsTokens_AndIsAdvertised_WithoutPrivateMembers()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await using var app = TestWebApp.Create(
            o => o.DefaultSigningAlgorithm = "ES256",
            b => b.AddSigningKey(new ECDsaSecurityKey(ec), "ES256", keyId: "ec1")
                  .AddEncryptionKey(new RsaSecurityKey(RSA.Create(2048)), keyId: "enc1"));

        var body = await Oidc.CodeFlowAsync(app);
        Assert.Equal("ES256", Oidc.Jwt(body.GetProperty("id_token").GetString()!).Alg);

        var discovery = JsonDocument.Parse(await app.Client.GetStringAsync("/.well-known/openid-configuration")).RootElement;
        Assert.Contains("ES256", discovery.GetProperty("id_token_signing_alg_values_supported").EnumerateArray().Select(a => a.GetString()));

        var keys = await JwksAsync(app);
        var jwk = keys.EnumerateArray().Single(k => k.GetProperty("kid").GetString() == "ec1");
        Assert.Equal("EC", jwk.GetProperty("kty").GetString());
        Assert.Equal("P-256", jwk.GetProperty("crv").GetString());
        foreach (var key in keys.EnumerateArray())
            foreach (var secret in new[] { "d", "p", "q", "dp", "dq", "qi" })
                Assert.False(key.TryGetProperty(secret, out _), $"JWKS leaked '{secret}'");
    }

    [Fact]
    public async Task ClientIdTokenAlgorithm_IsHonoured_AndHashesMatchIt()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        await using var app = TestWebApp.Create(
            o => o.StaticClients =
            [
                .. o.StaticClients,
                new Client
                {
                    ClientId = "es384-client",
                    ClientSecret = "secret",
                    AllowedGrantTypes = ["authorization_code", "implicit"],
                    ResponseTypes = ["code id_token"],
                    AllowedScopes = ["openid"],
                    RedirectUris = [Oidc.Callback],
                    RequirePkce = false,
                    RequireConsent = false,
                    IdTokenSignedResponseAlg = "ES384",
                },
            ],
            b => b.AddSigningKey(new RsaSecurityKey(RSA.Create(2048)), "RS256", keyId: "rs")
                  .AddSigningKey(new ECDsaSecurityKey(ec), "ES384", keyId: "es384"));
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "es384-client"), ("response_type", "code id_token"),
            ("scope", "openid"), ("redirect_uri", Oidc.Callback), ("nonce", "n"));
        var p = Oidc.ResponseParams(resp);
        var idToken = Oidc.Jwt(p["id_token"]!);

        Assert.Equal("ES384", idToken.Alg);
        Assert.Equal(TokenFactory.HalfHash(p["code"]!, "ES384"), idToken.GetClaim("c_hash").Value);
        Assert.Equal(32, idToken.GetClaim("c_hash").Value.Length);   // 24 bytes of SHA-384
    }

    [Fact]
    public async Task Production_RefusesGeneratedKeys()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => StartHostAsync("Production", _ => { }));
        Assert.Contains("generated keys", ex.Message);
    }

    [Fact]
    public async Task Production_StartsWithConfiguredKeys()
    {
        await using var app = await StartHostAsync("Production", _ => { }, b => b
            .AddSigningKey(new RsaSecurityKey(RSA.Create(2048)))
            .AddEncryptionKey(new RsaSecurityKey(RSA.Create(2048))));
        Assert.NotNull(app);
    }

    [Fact]
    public async Task KeyTypeNotMatchingAlgorithm_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => StartHostAsync("Development", _ => { },
            b => b.AddSigningKey(new RsaSecurityKey(RSA.Create(2048)), "ES256")));
        Assert.Contains("EC key", ex.Message);
    }

    // ── P4.4 ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://auth.example.com", "Production", "https")]
    [InlineData("auth.example.com", "Development", "absolute")]
    [InlineData("https://auth.example.com/?x=1", "Development", "query")]
    public async Task InvalidIssuer_FailsStartup(string issuer, string environment, string expected)
    {
        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            StartHostAsync(environment, o => o.Issuer = issuer, WithKeys));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void HttpIssuer_IsAllowedInDevelopment()
    {
        var result = Validate(o => o.Issuer = "http://localhost:5001", "Development");
        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(nameof(ProviderOptions.AccessTokenLifetimeSeconds))]
    [InlineData(nameof(ProviderOptions.AuthorizationCodeLifetimeSeconds))]
    public void NonPositiveLifetime_Fails(string property)
    {
        var result = Validate(o => typeof(ProviderOptions).GetProperty(property)!.SetValue(o, 0));
        Assert.Contains(result.Failures!, f => f.Contains(property));
    }

    [Fact]
    public void EnabledFeatures_WithoutWhatTheyNeed_Fail()
    {
        var result = Validate(o =>
        {
            o.VciEnabled = true;
            o.CibaEnabled = true;
            o.ResourceIndicatorsEnabled = true;
            o.RequirePushedAuthorization = true;
            o.MtlsClientCertificateHeader = "X-Client-Cert";
            o.LoginPath = "account/login";
        });

        foreach (var expected in new[] { "IssueCredential", "ProcessBackchannelAuthenticationRequest",
                     "AllowedResources", "PushedAuthorizationEnabled", "MtlsTrustedProxies", "LoginPath" })
            Assert.Contains(result.Failures!, f => f.Contains(expected));
    }

    [Fact]
    public void InconsistentClients_Fail()
    {
        var result = Validate(o => o.StaticClients =
        [
            new Client { ClientId = "dup", ClientSecret = "s" },
            new Client { ClientId = "dup", ClientSecret = "s" },
            new Client { ClientId = "no-secret" },
            new Client { ClientId = "pk", TokenEndpointAuthMethod = "private_key_jwt" },
            new Client { ClientId = "public", TokenEndpointAuthMethod = "none", ClientSecret = "oops" },
        ]);

        Assert.Contains(result.Failures!, f => f.Contains("'dup' is configured more than once"));
        Assert.Contains(result.Failures!, f => f.Contains("'no-secret'"));
        Assert.Contains(result.Failures!, f => f.Contains("'pk'") && f.Contains("JwksJson"));
        Assert.Contains(result.Failures!, f => f.Contains("'public'"));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static void WithKeys(NetOidcBuilder b) =>
        b.AddSigningKey(new RsaSecurityKey(RSA.Create(2048))).AddEncryptionKey(new RsaSecurityKey(RSA.Create(2048)));

    private static ValidateOptionsResult Validate(Action<ProviderOptions> configure, string environment = "Production")
    {
        var opts = new ProviderOptions { Issuer = "https://auth.example.com" };
        configure(opts);
        var env = new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = environment };
        return new ProviderOptionsValidator(env).Validate(null, opts);
    }

    private static async Task<WebApplication> StartHostAsync(
        string environment, Action<ProviderOptions> configure, Action<NetOidcBuilder>? builder = null)
    {
        var appBuilder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        appBuilder.WebHost.UseTestServer();
        var oidc = appBuilder.Services.AddNetOidc(o =>
        {
            o.Issuer = "https://auth.example.com";
            configure(o);
        });
        builder?.Invoke(oidc);
        var app = appBuilder.Build();
        app.MapNetOidc();
        await app.StartAsync();
        return app;
    }

    private static Task<HttpResponseMessage> UserInfoAsync(TestWebApp app, string token)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return app.Client.SendAsync(req);
    }
}
