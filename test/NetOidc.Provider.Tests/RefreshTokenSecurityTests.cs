using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.DPoP;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P1.8 (refresh rotation, reuse detection, binding).</summary>
public sealed class RefreshTokenSecurityTests
{
    private const string TokenEndpoint = "https://auth.test.example.com/connect/token";

    [Fact]
    public async Task Rotation_IssuesNewToken_AndOldTokenCannotBeReused()
    {
        await using var app = TestWebApp.Create();
        var rt1 = await CodeFlowRefreshTokenAsync(app);

        var r1 = await RefreshAsync(app, rt1);
        Assert.Equal(HttpStatusCode.OK, r1.StatusCode);
        var rt2 = RefreshTokenFrom(await r1.Content.ReadAsStringAsync());
        Assert.NotEqual(rt1, rt2);

        await AssertInvalidGrantAsync(await RefreshAsync(app, rt1));
    }

    [Fact]
    public async Task Reuse_RevokesTheWholeFamily()
    {
        await using var app = TestWebApp.Create();
        var rt1 = await CodeFlowRefreshTokenAsync(app);
        var rt2 = RefreshTokenFrom(await (await RefreshAsync(app, rt1)).Content.ReadAsStringAsync());

        // An attacker replays the stolen, already-rotated token…
        await AssertInvalidGrantAsync(await RefreshAsync(app, rt1));

        // …and the legitimate client's current token is revoked with it.
        await AssertInvalidGrantAsync(await RefreshAsync(app, rt2));
    }

    [Fact]
    public async Task Revocation_RevokesTheWholeFamily()
    {
        await using var app = TestWebApp.Create();
        var rt1 = await CodeFlowRefreshTokenAsync(app);
        var rt2 = RefreshTokenFrom(await (await RefreshAsync(app, rt1)).Content.ReadAsStringAsync());

        var revoke = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/revoke")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent([new("token", rt2), new("token_type_hint", "refresh_token")]),
        });
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        await AssertInvalidGrantAsync(await RefreshAsync(app, rt2));
    }

    [Fact]
    public async Task Introspection_ReportsRotatedTokenInactive()
    {
        await using var app = TestWebApp.Create();
        var rt1 = await CodeFlowRefreshTokenAsync(app);
        await RefreshAsync(app, rt1);

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent([new("token", rt1), new("token_type_hint", "refresh_token")]),
        });

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.False(doc.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task BoundToken_RequiresTheSameDPoPKey()
    {
        await using var app = TestWebApp.Create(o => o.DPoPEnabled = true);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rt = await IssueBoundTokenAsync(app, key);

        await AssertInvalidGrantAsync(await RefreshAsync(app, rt));                           // no proof
        rt = await IssueBoundTokenAsync(app, key);
        await AssertInvalidGrantAsync(await RefreshAsync(app, rt, DPoPProof(otherKey)));      // wrong key
        rt = await IssueBoundTokenAsync(app, key);
        Assert.Equal(HttpStatusCode.OK, (await RefreshAsync(app, rt, DPoPProof(key))).StatusCode);
    }

    [Fact]
    public async Task RotatedBoundToken_StaysBoundToOriginalKey()
    {
        await using var app = TestWebApp.Create(o => o.DPoPEnabled = true);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rt1 = await IssueBoundTokenAsync(app, key);

        var r1 = await RefreshAsync(app, rt1, DPoPProof(key));
        var rt2 = RefreshTokenFrom(await r1.Content.ReadAsStringAsync());

        await AssertInvalidGrantAsync(await RefreshAsync(app, rt2, DPoPProof(otherKey)));
    }

    [Fact]
    public async Task ConfidentialClientTokens_AreNotKeyBound()
    {
        // RFC 9449 §5: confidential clients are sender-constrained by client authentication.
        await using var app = TestWebApp.Create(o => o.DPoPEnabled = true);
        var service = app.Services.GetRequiredService<RefreshTokenService>();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var rt = await service.IssueAsync(TestClient("client_secret_basic"), "alice", ["openid"], [], null,
            Thumbprint(key), cnfX5tS256: null, CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, (await RefreshAsync(app, rt.Value)).StatusCode);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Issues a refresh token as the service would for a public client, owned by test-client
    /// so the test can redeem it with test-client's credentials.
    /// </summary>
    private static async Task<string> IssueBoundTokenAsync(TestWebApp app, ECDsa key) =>
        (await app.Services.GetRequiredService<RefreshTokenService>().IssueAsync(
            TestClient("none"), "alice", ["openid"], [], null,
            Thumbprint(key), cnfX5tS256: null, CancellationToken.None)).Value;

    private static Client TestClient(string authMethod) => new()
    {
        ClientId = "test-client",
        TokenEndpointAuthMethod = authMethod,
    };

    private static async Task<string> CodeFlowRefreshTokenAsync(TestWebApp app)
    {
        await app.Client.PostAsync("/test/signin", new FormUrlEncodedContent([new("subject", "alice")]));
        var authz = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code&scope=openid" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback");
        var code = HttpUtility.ParseQueryString(authz.Headers.Location!.Query)["code"]!;

        var token = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", "https://client.test.example.com/callback"),
            ]),
        });
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        return RefreshTokenFrom(await token.Content.ReadAsStringAsync());
    }

    private static Task<HttpResponseMessage> RefreshAsync(TestWebApp app, string rt, string? dpop = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent([new("grant_type", "refresh_token"), new("refresh_token", rt)]),
        };
        if (dpop is not null) req.Headers.Add("DPoP", dpop);
        return app.Client.SendAsync(req);
    }

    private static string RefreshTokenFrom(string json) =>
        JsonDocument.Parse(json).RootElement.GetProperty("refresh_token").GetString()!;

    private static AuthenticationHeaderValue Basic() =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));

    private static string PublicJwkJson(ECDsa key)
    {
        var p = key.ExportParameters(false);
        return JsonSerializer.Serialize(new
        {
            kty = "EC",
            crv = "P-256",
            x = Base64UrlEncoder.Encode(p.Q.X!),
            y = Base64UrlEncoder.Encode(p.Q.Y!),
        });
    }

    private static string Thumbprint(ECDsa key) =>
        DPopProofValidator.ComputeJwkThumbprint(new JsonWebKey(PublicJwkJson(key)));

    private static string DPoPProof(ECDsa key) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString(),
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["htm"] = "POST",
                ["htu"] = TokenEndpoint,
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = JsonDocument.Parse(PublicJwkJson(key)).RootElement,
            },
        });

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.BadRequest, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal("invalid_grant", JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }
}
