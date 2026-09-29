using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P2.4 (UserInfo token checks) and P2.5 (revoking a
/// refresh token revokes the access tokens of the same grant).
/// </summary>
public sealed class UserInfoSecurityTests
{
    // ── P2.4 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task MissingToken_ReturnsBearerChallengeWithoutError()
    {
        await using var app = TestWebApp.Create();

        var resp = await app.Client.GetAsync("/connect/userinfo");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        var challenge = resp.Headers.WwwAuthenticate.ToString();
        Assert.StartsWith("Bearer", challenge);
        Assert.DoesNotContain("error=", challenge);
    }

    [Fact]
    public async Task RevokedToken_IsRejected()
    {
        await using var app = TestWebApp.Create();
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "openid");
        await app.Services.GetRequiredService<IAdapter<AccessToken>>().RemoveAsync(new JsonWebToken(token).Id);

        var resp = await UserInfoAsync(app, "Bearer", token);

        AssertChallenge(resp, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task TokenWithoutOpenIdScope_ReturnsInsufficientScope()
    {
        await using var app = TestWebApp.Create();
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "profile");

        var resp = await UserInfoAsync(app, "Bearer", token);

        AssertChallenge(resp, HttpStatusCode.Forbidden, "insufficient_scope");
    }

    [Fact]
    public async Task DPoPBoundToken_PresentedAsBearer_IsRejected()
    {
        await using var app = TestWebApp.Create(o => o.DPoPEnabled = true);
        var token = await StoreBoundTokenAsync(app, jkt: "some-thumbprint", x5t: null);

        var resp = await UserInfoAsync(app, "Bearer", token);

        AssertChallenge(resp, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task UnboundToken_PresentedAsDPoP_IsRejected()
    {
        await using var app = TestWebApp.Create(o => o.DPoPEnabled = true);
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "openid");

        var resp = await UserInfoAsync(app, "DPoP", token);

        AssertChallenge(resp, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task CertificateBoundToken_RequiresTheSameCertificate()
    {
        using var cert = SelfSigned("CN=bound");
        using var other = SelfSigned("CN=other");
        await using var app = TestWebApp.Create(o => o.MtlsClientCertificateHeader = "X-Client-Cert");
        var thumbprint = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(cert.GetCertHash(HashAlgorithmName.SHA256));
        var token = await StoreBoundTokenAsync(app, jkt: null, x5t: thumbprint);

        AssertChallenge(await UserInfoAsync(app, "Bearer", token), HttpStatusCode.Unauthorized, "invalid_token");
        AssertChallenge(await UserInfoAsync(app, "Bearer", token, other), HttpStatusCode.Unauthorized, "invalid_token");
        Assert.Equal(HttpStatusCode.OK, (await UserInfoAsync(app, "Bearer", token, cert)).StatusCode);
    }

    // ── P2.5 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RevokingRefreshToken_RevokesAccessTokensOfTheGrant()
    {
        await using var app = TestWebApp.Create();
        var (accessToken, refreshToken) = await CodeFlowAsync(app);
        Assert.Equal(HttpStatusCode.OK, (await UserInfoAsync(app, "Bearer", accessToken)).StatusCode);

        var revoke = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/revoke")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent([new("token", refreshToken), new("token_type_hint", "refresh_token")]),
        });
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        AssertChallenge(await UserInfoAsync(app, "Bearer", accessToken), HttpStatusCode.Unauthorized, "invalid_token");
        using var introspection = await IntrospectAsync(app, accessToken);
        Assert.False(introspection.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task RefreshTokenReuse_RevokesAccessTokensOfTheFamily()
    {
        await using var app = TestWebApp.Create();
        var (_, rt1) = await CodeFlowAsync(app);
        var refreshed = JsonDocument.Parse(await (await RefreshAsync(app, rt1)).Content.ReadAsStringAsync());
        var latestAccessToken = refreshed.RootElement.GetProperty("access_token").GetString()!;

        await RefreshAsync(app, rt1);   // replay → family revoked

        AssertChallenge(await UserInfoAsync(app, "Bearer", latestAccessToken), HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task ClientCredentialsToken_IsUnaffectedByGrantChecks()
    {
        await using var app = TestWebApp.Create();
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials"), new("scope", "profile")]),
        });
        var token = JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        var introspection = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([new("token", token)]),
        });
        using var doc = JsonDocument.Parse(await introspection.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("active").GetBoolean());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static async Task<string> StoreBoundTokenAsync(TestWebApp app, string? jkt, string? x5t)
    {
        var id = Guid.NewGuid().ToString("N");
        await app.Services.GetRequiredService<IAdapter<AccessToken>>().StoreAsync(id, new AccessToken
        {
            TokenId = id,
            GrantId = id,
            ClientId = "test-client",
            Subject = "alice",
            Scopes = ["openid"],
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            CnfJwkThumbprint = jkt,
            CnfX5tS256 = x5t,
        }, TimeSpan.FromHours(1));
        return app.Services.GetRequiredService<TokenFactory>()
            .CreateAccessToken(id, "alice", "test-client", ["openid"], jkt, x5t);
    }

    private static Task<HttpResponseMessage> UserInfoAsync(
        TestWebApp app, string scheme, string token, X509Certificate2? cert = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        if (cert is not null) req.Headers.Add("X-Client-Cert", Uri.EscapeDataString(cert.ExportCertificatePem()));
        return app.Client.SendAsync(req);
    }

    private static async Task<(string AccessToken, string RefreshToken)> CodeFlowAsync(TestWebApp app)
    {
        await app.Client.PostAsync("/test/signin", new FormUrlEncodedContent([new("subject", "alice")]));
        var authz = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code&scope=openid");
        var code = HttpUtility.ParseQueryString(authz.Headers.Location!.Query)["code"]!;
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent([new("grant_type", "authorization_code"), new("code", code)]),
        });
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return (doc.RootElement.GetProperty("access_token").GetString()!,
                doc.RootElement.GetProperty("refresh_token").GetString()!);
    }

    private static Task<HttpResponseMessage> RefreshAsync(TestWebApp app, string rt) =>
        app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent([new("grant_type", "refresh_token"), new("refresh_token", rt)]),
        });

    private static async Task<JsonDocument> IntrospectAsync(TestWebApp app, string token)
    {
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Headers = { Authorization = Basic() },
            Content = new FormUrlEncodedContent([new("token", token)]),
        });
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
    }

    private static void AssertChallenge(HttpResponseMessage resp, HttpStatusCode status, string error)
    {
        Assert.Equal(status, resp.StatusCode);
        Assert.Contains($"error=\"{error}\"", resp.Headers.WwwAuthenticate.ToString());
    }

    private static X509Certificate2 SelfSigned(string subject)
    {
        using var rsa = RSA.Create(2048);
        return new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static AuthenticationHeaderValue Basic() =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
}
