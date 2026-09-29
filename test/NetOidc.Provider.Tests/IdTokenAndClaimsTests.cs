using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P3.4 (ID token content), P3.5 (claims parameter and
/// scope-based claim release) and P3.6 (pairwise subjects end to end).
/// </summary>
public sealed class IdTokenAndClaimsTests
{
    // ── P3.4 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task HybridIdToken_CarriesCHashAndAtHash()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "hybrid-client"), ("response_type", "code id_token token"), ("scope", "openid"),
            ("redirect_uri", Oidc.Callback), ("nonce", "n1"));

        var p = Oidc.ResponseParams(resp);
        var idToken = Oidc.Jwt(p["id_token"]!);
        Assert.Equal(TokenFactory.HalfHash(p["code"]!), idToken.GetClaim("c_hash").Value);
        Assert.Equal(TokenFactory.HalfHash(p["access_token"]!), idToken.GetClaim("at_hash").Value);
        Assert.Equal("n1", idToken.GetClaim("nonce").Value);
    }

    [Fact]
    public async Task AuthTime_IsTheLoginTime_NotTheIssuanceTime()
    {
        await using var app = TestWebApp.Create();
        var loggedInAt = DateTimeOffset.UtcNow.AddMinutes(-30);
        await Oidc.SignInAsync(app, "alice", authTime: loggedInAt);

        var authz = await Oidc.AuthorizeAsync(app,
            ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"), ("redirect_uri", Oidc.Callback));
        var token = await Oidc.TokenAsync(app,
            [new("grant_type", "authorization_code"), new("code", Oidc.ResponseParams(authz)["code"]!), new("redirect_uri", Oidc.Callback)],
            ("test-client", "test-secret"));
        var idToken = Oidc.Jwt(JsonDocument.Parse(await token.Content.ReadAsStringAsync())
            .RootElement.GetProperty("id_token").GetString()!);

        Assert.Equal(loggedInAt.ToUnixTimeSeconds(), long.Parse(idToken.GetClaim("auth_time").Value));
    }

    [Fact]
    public async Task IdToken_IsEncryptedAtTheTokenEndpoint_WhenClientRegisteredEncryption()
    {
        using var rsa = RSA.Create(2048);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(false)));
        await using var app = TestWebApp.Create(o => o.StaticClients =
        [
            .. o.StaticClients,
            new Client
            {
                ClientId = "enc-client",
                ClientSecret = "enc-secret",
                AllowedGrantTypes = ["authorization_code"],
                AllowedScopes = ["openid"],
                RedirectUris = [Oidc.Callback],
                RequirePkce = false,
                RequireConsent = false,
                IdTokenEncryptedResponseAlg = "RSA-OAEP",
                IdTokenEncryptedResponseEnc = "A256CBC-HS512",
                JwksJson = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", use = "enc", n = jwk.N, e = jwk.E } } }),
            },
        ]);

        var body = await Oidc.CodeFlowAsync(app, clientId: "enc-client", secret: "enc-secret");

        Assert.Equal(5, body.GetProperty("id_token").GetString()!.Split('.').Length);   // JWE compact
    }

    // ── P3.5 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ScopeClaims_GoToUserInfo_NotToTheIdToken_ForCodeFlow()
    {
        await using var app = TestWebApp.Create();
        var body = await Oidc.CodeFlowAsync(app, scope: "openid profile");

        Assert.False(Oidc.Jwt(body.GetProperty("id_token").GetString()!).TryGetClaim("name", out _));

        using var userInfo = await UserInfoAsync(app, body.GetProperty("access_token").GetString()!);
        Assert.Equal("Test alice", userInfo.RootElement.GetProperty("name").GetString());
        // email is known to the claims source but no scope or request released it.
        Assert.False(userInfo.RootElement.TryGetProperty("email", out _));
    }

    [Fact]
    public async Task ClaimsRequest_ReleasesIndividualClaims_ToIdTokenAndUserInfo()
    {
        await using var app = TestWebApp.Create();
        var claims = """{"id_token":{"email":{"essential":true}},"userinfo":{"email":null}}""";

        var body = await Oidc.CodeFlowAsync(app, scope: "openid", extra: ("claims", claims));

        Assert.Equal("alice@example.com", Oidc.Jwt(body.GetProperty("id_token").GetString()!).GetClaim("email").Value);
        using var userInfo = await UserInfoAsync(app, body.GetProperty("access_token").GetString()!);
        Assert.Equal("alice@example.com", userInfo.RootElement.GetProperty("email").GetString());
    }

    [Fact]
    public async Task ClaimsRequest_CannotOverrideProtocolClaims()
    {
        await using var app = TestWebApp.Create(o => o.FindUserClaims = (_, _) =>
            Task.FromResult<IReadOnlyDictionary<string, object>>(new Dictionary<string, object> { ["sub"] = "evil" }));

        var body = await Oidc.CodeFlowAsync(app, extra: ("claims", """{"id_token":{"sub":null}}"""));

        Assert.Equal("alice", Oidc.Jwt(body.GetProperty("id_token").GetString()!).Subject);
    }

    [Fact]
    public async Task MalformedClaimsRequest_IsRejected()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", Oidc.Callback), ("claims", "[not an object"));

        Oidc.AssertRedirectError(resp, "invalid_request");
    }

    [Fact]
    public async Task EssentialAcr_NotAchieved_DeniesAccess()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice", acr: "urn:acr:basic");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"), ("redirect_uri", Oidc.Callback),
            ("claims", """{"id_token":{"acr":{"essential":true,"values":["urn:acr:mfa"]}}}"""));

        Oidc.AssertRedirectError(resp, "access_denied");
    }

    [Fact]
    public async Task ImplicitIdTokenOnly_CarriesScopeClaims()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "implicit-client"), ("response_type", "id_token"), ("scope", "openid profile"),
            ("redirect_uri", Oidc.Callback), ("nonce", "n"));

        // OIDC Core §5.4: no access token, so the scope claims are in the ID token.
        Assert.Equal("Test alice", Oidc.Jwt(Oidc.ResponseParams(resp)["id_token"]!).GetClaim("name").Value);
    }

    // ── P3.6 ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Pairwise_ClientsSeeTheirOwnSub_AndTheClaimsSourceSeesTheLocalSubject()
    {
        var seen = new List<string>();
        await using var app = TestWebApp.Create(o =>
        {
            o.SubjectType = "pairwise";
            o.PairwiseSalt = "a-secret-pairwise-salt-of-32-bytes!!";
            o.FindUserClaims = (req, _) =>
            {
                seen.Add(req.Subject);
                return Task.FromResult<IReadOnlyDictionary<string, object>>(
                    new Dictionary<string, object> { ["name"] = "Alice" });
            };
        });

        var body = await Oidc.CodeFlowAsync(app, scope: "openid profile");
        var idSub = Oidc.Jwt(body.GetProperty("id_token").GetString()!).Subject;
        var accessToken = body.GetProperty("access_token").GetString()!;

        using var userInfo = await UserInfoAsync(app, accessToken);
        Assert.NotEqual("alice", idSub);
        Assert.Equal(idSub, userInfo.RootElement.GetProperty("sub").GetString());
        Assert.Equal(idSub, Oidc.Jwt(accessToken).Subject);
        Assert.All(seen, s => Assert.Equal("alice", s));
        Assert.NotEmpty(seen);

        var introspection = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/introspect")
        {
            Headers = { Authorization = Oidc.Basic("test-client", "test-secret") },
            Content = new FormUrlEncodedContent([new("token", accessToken)]),
        });
        using var intro = JsonDocument.Parse(await introspection.Content.ReadAsStringAsync());
        Assert.Equal(idSub, intro.RootElement.GetProperty("sub").GetString());
    }

    private static async Task<JsonDocument> UserInfoAsync(TestWebApp app, string accessToken)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var resp = await app.Client.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.OK, body);
        return JsonDocument.Parse(body);
    }
}
