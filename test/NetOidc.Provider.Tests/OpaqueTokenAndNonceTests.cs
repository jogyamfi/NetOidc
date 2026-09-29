using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.DPoP;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P4.5 (opaque access tokens) and P4.3 (shared nonces).</summary>
public sealed class OpaqueTokenAndNonceTests
{
    // ── P4.5 ────────────────────────────────────────────────────────────────

    private static TestWebApp CreateOpaqueApp(Action<ProviderOptions>? configure = null) => TestWebApp.Create(o =>
    {
        o.AccessTokenFormat = TokenFormat.Opaque;
        configure?.Invoke(o);
    });

    [Fact]
    public async Task OpaqueToken_IsARandomReference_AndWorksAtUserInfo()
    {
        await using var app = CreateOpaqueApp();
        var token = (await Oidc.CodeFlowAsync(app, scope: "openid profile")).GetProperty("access_token").GetString()!;

        Assert.DoesNotContain('.', token);
        var resp = await UserInfoAsync(app, token);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("Test alice", JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.GetProperty("name").GetString());
    }

    [Fact]
    public async Task OpaqueToken_IsStoredOnlyByItsHash()
    {
        await using var app = CreateOpaqueApp();
        var token = (await Oidc.CodeFlowAsync(app)).GetProperty("access_token").GetString()!;
        var store = app.Services.GetRequiredService<IAdapter<AccessToken>>();

        Assert.Null(await store.FindAsync(token));
        Assert.NotNull(await store.FindAsync(Token.AccessTokenService.OpaqueTokenId(token)));
    }

    [Fact]
    public async Task OpaqueToken_Introspects_AndRevokes()
    {
        await using var app = CreateOpaqueApp();
        var token = (await Oidc.CodeFlowAsync(app)).GetProperty("access_token").GetString()!;

        using var intro = await IntrospectAsync(app, token);
        Assert.True(intro.RootElement.GetProperty("active").GetBoolean());
        Assert.Equal("openid", intro.RootElement.GetProperty("scope").GetString());
        Assert.Equal("alice", intro.RootElement.GetProperty("sub").GetString());
        Assert.True(intro.RootElement.GetProperty("iat").GetInt64() > 0);

        var revoke = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/revoke")
        {
            Headers = { Authorization = Oidc.Basic("test-client", "test-secret") },
            Content = new FormUrlEncodedContent([new("token", token)]),
        });
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(app, token)).StatusCode);
    }

    [Fact]
    public async Task ClientOverride_SelectsTheFormat()
    {
        await using var app = TestWebApp.Create(o => o.StaticClients =
        [
            .. o.StaticClients,
            new Client
            {
                ClientId = "opaque-client",
                ClientSecret = "secret",
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
                AccessTokenFormat = TokenFormat.Opaque,
            },
        ]);

        var opaque = await Oidc.TokenAsync(app, [new("grant_type", "client_credentials")], ("opaque-client", "secret"));
        var jwt = await Oidc.TokenAsync(app, [new("grant_type", "client_credentials")], ("cc-client", "cc-secret"));

        Assert.DoesNotContain('.', AccessToken(await opaque.Content.ReadAsStringAsync()));
        Assert.Equal(2, AccessToken(await jwt.Content.ReadAsStringAsync()).Count(c => c == '.'));
    }

    // ── P4.3 DPoP server nonces ─────────────────────────────────────────────

    [Fact]
    public async Task DPoPNonce_RequiredNonce_IsChallengedThenAccepted()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DPoPEnabled = true;
            o.DPoPRequireNonce = true;
        });
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var first = await ClientCredentialsWithDPoPAsync(app, key, nonce: null);
        await Oidc.AssertErrorAsync(first, HttpStatusCode.BadRequest, "use_dpop_nonce");
        var nonce = first.Headers.GetValues("DPoP-Nonce").Single();

        var retry = await ClientCredentialsWithDPoPAsync(app, key, nonce);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal("DPoP", JsonDocument.Parse(await retry.Content.ReadAsStringAsync()).RootElement.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task DPoPNonce_ForgedNonce_IsRejected()
    {
        await using var app = TestWebApp.Create(o => { o.DPoPEnabled = true; o.DPoPRequireNonce = true; });
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await ClientCredentialsWithDPoPAsync(app, key, Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24)));

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "use_dpop_nonce");
    }

    [Fact]
    public void DPoPNonce_IsSharedAcrossInstancesWithTheSameSecret()
    {
        DPoPNonceService Instance(string secret) =>
            new(Options.Create(new ProviderOptions { DPoPNonceSecret = secret, DPoPRequireNonce = true }));

        var nonce = Instance("shared-secret").Issue();

        Assert.True(Instance("shared-secret").IsValid(nonce));
        Assert.False(Instance("other-secret").IsValid(nonce));
    }

    [Fact]
    public async Task VciNonces_GoThroughTheSharedAdapter()
    {
        await using var app = TestWebApp.Create(o => o.VciEnabled = true);

        var resp = await app.Client.PostAsync("/connect/nonce", content: null);
        var nonce = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.GetProperty("c_nonce").GetString()!;

        Assert.NotNull(await app.Services.GetRequiredService<IAdapter<CredentialNonce>>().FindAsync(nonce));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string AccessToken(string json) =>
        JsonDocument.Parse(json).RootElement.GetProperty("access_token").GetString()!;

    private static Task<HttpResponseMessage> ClientCredentialsWithDPoPAsync(TestWebApp app, ECDsa key, string? nonce)
    {
        var p = key.ExportParameters(false);
        var jwk = JsonSerializer.Serialize(new
        {
            kty = "EC", crv = "P-256", x = Base64UrlEncoder.Encode(p.Q.X!), y = Base64UrlEncoder.Encode(p.Q.Y!),
        });
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString(),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["htm"] = "POST",
            ["htu"] = "https://auth.test.example.com/connect/token",
        };
        if (nonce is not null) claims["nonce"] = nonce;
        var proof = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = JsonDocument.Parse(jwk).RootElement,
            },
        });
        return Oidc.TokenAsync(app, [new("grant_type", "client_credentials")], ("cc-client", "cc-secret"), dpop: proof);
    }

    private static Task<HttpResponseMessage> UserInfoAsync(TestWebApp app, string token)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return app.Client.SendAsync(req);
    }

    private static async Task<JsonDocument> IntrospectAsync(TestWebApp app, string token)
    {
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Headers = { Authorization = Oidc.Basic("test-client", "test-secret") },
            Content = new FormUrlEncodedContent([new("token", token)]),
        });
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
    }
}
