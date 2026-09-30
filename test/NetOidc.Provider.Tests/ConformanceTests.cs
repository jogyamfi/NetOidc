using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.DPoP;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P3.1 (public clients), P3.7 (JAR), P3.8 (PKCE),
/// P3.9 (code replay), P3.10 (grant/response types), P3.11 (refresh), P3.12 (resource
/// indicators) and P3.13 (FAPI runtime enforcement).
/// </summary>
public sealed class ConformanceTests
{
    private static Client PublicClient => new()
    {
        ClientId = "spa",
        TokenEndpointAuthMethod = "none",
        AllowedGrantTypes = ["authorization_code", "refresh_token"],
        AllowedScopes = ["openid"],
        RedirectUris = [Oidc.Callback],
        RequirePkce = false,   // public clients need PKCE regardless
        RequireConsent = false,
    };

    private static TestWebApp CreateApp(Action<ProviderOptions>? configure = null, params Client[] clients) =>
        TestWebApp.Create(o =>
        {
            o.StaticClients = [.. o.StaticClients, .. clients];
            configure?.Invoke(o);
        });

    private static Task<HttpResponseMessage> AuthorizeCodeAsync(
        TestWebApp app, string clientId = "test-client", params (string, string)[] extra) =>
        Oidc.AuthorizeAsync(app,
        [
            ("client_id", clientId), ("response_type", "code"), ("scope", "openid"), ("redirect_uri", Oidc.Callback),
            .. extra,
        ]);

    private static Task<HttpResponseMessage> RedeemAsync(TestWebApp app, string code, params (string, string)[] extra) =>
        RedeemCoreAsync(app, code, ("test-client", "test-secret"), extra);

    private static Task<HttpResponseMessage> RedeemPublicAsync(TestWebApp app, string code, params (string, string)[] extra) =>
        RedeemCoreAsync(app, code, null, extra);

    private static Task<HttpResponseMessage> RedeemCoreAsync(
        TestWebApp app, string code, (string, string)? basic, (string, string)[] extra) =>
        Oidc.TokenAsync(app,
        [
            new("grant_type", "authorization_code"), new("code", code), new("redirect_uri", Oidc.Callback),
            .. extra.Select(e => new KeyValuePair<string, string>(e.Item1, e.Item2)),
        ], basic);

    // ── P3.1 Public clients ─────────────────────────────────────────────────

    [Fact]
    public async Task PublicClient_CompletesCodeFlowWithPkce()
    {
        await using var app = CreateApp(null, PublicClient);
        await Oidc.SignInAsync(app, "alice");

        var authz = await AuthorizeCodeAsync(app, "spa",
            ("code_challenge", Oidc.Challenge), ("code_challenge_method", "S256"));
        var token = await RedeemPublicAsync(app, Oidc.ResponseParams(authz)["code"]!,
            ("client_id", "spa"), ("code_verifier", Oidc.Verifier));

        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
    }

    [Fact]
    public async Task PublicClient_MustUsePkce_EvenIfRequirePkceIsFalse()
    {
        await using var app = CreateApp(null, PublicClient);
        await Oidc.SignInAsync(app, "alice");

        Oidc.AssertRedirectError(await AuthorizeCodeAsync(app, "spa"), "invalid_request");
    }

    [Fact]
    public async Task PublicClient_RefreshTokenIsBoundToItsDPoPKey()
    {
        await using var app = CreateApp(o => o.DPoPEnabled = true, PublicClient);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await Oidc.SignInAsync(app, "alice");

        var authz = await AuthorizeCodeAsync(app, "spa", ("code_challenge", Oidc.Challenge), ("code_challenge_method", "S256"));
        var token = await Oidc.TokenAsync(app,
        [
            new("grant_type", "authorization_code"), new("code", Oidc.ResponseParams(authz)["code"]!),
            new("redirect_uri", Oidc.Callback), new("client_id", "spa"), new("code_verifier", Oidc.Verifier),
        ], dpop: DPoP(key));
        var rt = JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("refresh_token").GetString()!;

        var stolen = await Oidc.TokenAsync(app,
            [new("grant_type", "refresh_token"), new("refresh_token", rt), new("client_id", "spa")], dpop: DPoP(other));
        await Oidc.AssertErrorAsync(stolen, HttpStatusCode.BadRequest, "invalid_grant");
    }

    // ── P3.7 JAR ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Jar_ParametersOutsideTheRequestObjectAreIgnored()
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateApp(o => o.JarEnabled = true, JarClient(rsa));
        await Oidc.SignInAsync(app, "alice");

        var request = RequestObject(rsa, new() { ["state"] = "signed-state" });
        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "jar-client"), ("request", request), ("state", "unsigned-state"), ("prompt", "login"));

        // Neither the unsigned state nor the unsigned prompt=login took effect.
        Assert.Equal("signed-state", Oidc.ResponseParams(resp)["state"]);
        Assert.NotNull(Oidc.ResponseParams(resp)["code"]);
    }

    [Fact]
    public async Task Jar_RequestUriByReference_IsNotSupported()
    {
        await using var app = CreateApp(o => o.JarEnabled = true);
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"),
            ("request_uri", "https://client.example.com/request.jwt"), ("redirect_uri", Oidc.Callback));

        Oidc.AssertRedirectError(resp, "request_uri_not_supported");
    }

    [Fact]
    public async Task JarRequireSignedRequestObject_RejectsPlainRequests()
    {
        await using var app = CreateApp(o => { o.JarEnabled = true; o.JarRequireSignedRequestObject = true; });
        await Oidc.SignInAsync(app, "alice");

        Oidc.AssertRedirectError(await AuthorizeCodeAsync(app), "invalid_request");
    }

    // ── P3.8 PKCE ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("plain")]
    public async Task Pkce_OnlyS256IsAcceptedByDefault(string? method)
    {
        await using var app = CreateApp();
        await Oidc.SignInAsync(app, "alice");
        var extra = new List<(string, string)> { ("code_challenge", Oidc.Verifier) };
        if (method is not null) extra.Add(("code_challenge_method", method));

        Oidc.AssertRedirectError(await AuthorizeCodeAsync(app, "test-client", [.. extra]), "invalid_request");
    }

    [Fact]
    public async Task Pkce_PlainIsAcceptedWhenAllowed()
    {
        await using var app = CreateApp(o => o.AllowPlainPkce = true);
        await Oidc.SignInAsync(app, "alice");

        var authz = await AuthorizeCodeAsync(app, "test-client", ("code_challenge", Oidc.Verifier));
        var token = await RedeemAsync(app, Oidc.ResponseParams(authz)["code"]!, ("code_verifier", Oidc.Verifier));

        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
    }

    [Fact]
    public async Task Pkce_MalformedChallenge_IsRejected()
    {
        await using var app = CreateApp();
        await Oidc.SignInAsync(app, "alice");

        var resp = await AuthorizeCodeAsync(app, "test-client", ("code_challenge", "short"), ("code_challenge_method", "S256"));

        Oidc.AssertRedirectError(resp, "invalid_request");
    }

    [Fact]
    public async Task Pkce_VerifierWithoutChallenge_IsRejected()
    {
        await using var app = CreateApp();
        await Oidc.SignInAsync(app, "alice");

        var authz = await AuthorizeCodeAsync(app);
        var token = await RedeemAsync(app, Oidc.ResponseParams(authz)["code"]!, ("code_verifier", Oidc.Verifier));

        await Oidc.AssertErrorAsync(token, HttpStatusCode.BadRequest, "invalid_grant");
    }

    // ── P3.9 Code replay ────────────────────────────────────────────────────

    [Fact]
    public async Task CodeReplay_RevokesTokensIssuedFromTheCode()
    {
        await using var app = CreateApp();
        await Oidc.SignInAsync(app, "alice");
        var code = Oidc.ResponseParams(await AuthorizeCodeAsync(app))["code"]!;

        var first = JsonDocument.Parse(await (await RedeemAsync(app, code)).Content.ReadAsStringAsync()).RootElement;
        await Oidc.AssertErrorAsync(await RedeemAsync(app, code), HttpStatusCode.BadRequest, "invalid_grant");

        var userinfo = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userinfo.Headers.Authorization = new AuthenticationHeaderValue("Bearer", first.GetProperty("access_token").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.Client.SendAsync(userinfo)).StatusCode);

        var refresh = await Oidc.TokenAsync(app,
            [new("grant_type", "refresh_token"), new("refresh_token", first.GetProperty("refresh_token").GetString()!)],
            ("test-client", "test-secret"));
        await Oidc.AssertErrorAsync(refresh, HttpStatusCode.BadRequest, "invalid_grant");
    }

    // ── P3.10 Grant and response types ──────────────────────────────────────

    [Fact]
    public async Task ResponseTypeNotRegistered_IsUnauthorized()
    {
        await using var app = CreateApp();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code id_token"),
            ("scope", "openid"), ("redirect_uri", Oidc.Callback), ("nonce", "n"));

        Oidc.AssertRedirectError(resp, "unauthorized_client");
    }

    [Fact]
    public async Task ClientWithoutRefreshGrant_GetsNoRefreshToken_AndCannotRefresh()
    {
        await using var app = CreateApp(null, new Client
        {
            ClientId = "no-refresh",
            ClientSecret = "nr-secret",
            AllowedGrantTypes = ["authorization_code"],
            AllowedScopes = ["openid"],
            RedirectUris = [Oidc.Callback],
            RequirePkce = false,
            RequireConsent = false,
        });

        var body = await Oidc.CodeFlowAsync(app, clientId: "no-refresh", secret: "nr-secret");

        Assert.False(body.TryGetProperty("refresh_token", out _));
        var refresh = await Oidc.TokenAsync(app, [new("grant_type", "refresh_token"), new("refresh_token", "x")],
            ("no-refresh", "nr-secret"));
        await Oidc.AssertErrorAsync(refresh, HttpStatusCode.BadRequest, "unauthorized_client");
    }

    [Fact]
    public async Task AuthorizationCodeGrant_RequiresTheGrantType()
    {
        await using var app = CreateApp();
        var resp = await Oidc.TokenAsync(app, [new("grant_type", "authorization_code"), new("code", "x")], ("cc-client", "cc-secret"));
        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "unauthorized_client");
    }

    // ── P3.11 Refresh ───────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_CanNarrowScope_ButNotWiden_AndReturnsAnIdToken()
    {
        await using var app = CreateApp();
        var body = await Oidc.CodeFlowAsync(app, scope: "openid profile");
        var rt = body.GetProperty("refresh_token").GetString()!;

        var narrowed = JsonDocument.Parse(await (await Oidc.TokenAsync(app,
            [new("grant_type", "refresh_token"), new("refresh_token", rt), new("scope", "openid")],
            ("test-client", "test-secret"))).Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("openid", narrowed.GetProperty("scope").GetString());
        Assert.True(narrowed.TryGetProperty("id_token", out var idToken));
        Assert.Equal(Oidc.Jwt(body.GetProperty("id_token").GetString()!).GetClaim("auth_time").Value,
            Oidc.Jwt(idToken.GetString()!).GetClaim("auth_time").Value);

        // The rotated refresh token still carries the original scopes.
        var rt2 = narrowed.GetProperty("refresh_token").GetString()!;
        var widened = await Oidc.TokenAsync(app,
            [new("grant_type", "refresh_token"), new("refresh_token", rt2), new("scope", "openid profile")],
            ("test-client", "test-secret"));
        Assert.Equal(HttpStatusCode.OK, widened.StatusCode);

        var rt3 = JsonDocument.Parse(await widened.Content.ReadAsStringAsync()).RootElement.GetProperty("refresh_token").GetString()!;
        var escalated = await Oidc.TokenAsync(app,
            [new("grant_type", "refresh_token"), new("refresh_token", rt3), new("scope", "openid email")],
            ("test-client", "test-secret"));
        await Oidc.AssertErrorAsync(escalated, HttpStatusCode.BadRequest, "invalid_scope");
    }

    [Fact]
    public async Task Refresh_WithoutRotation_KeepsTheTokenForConfidentialClients()
    {
        await using var app = CreateApp(o => o.RotateRefreshTokens = false);
        var rt = (await Oidc.CodeFlowAsync(app)).GetProperty("refresh_token").GetString()!;

        for (var i = 0; i < 2; i++)
        {
            var resp = JsonDocument.Parse(await (await Oidc.TokenAsync(app,
                [new("grant_type", "refresh_token"), new("refresh_token", rt)],
                ("test-client", "test-secret"))).Content.ReadAsStringAsync()).RootElement;
            Assert.Equal(rt, resp.GetProperty("refresh_token").GetString());
        }
    }

    // ── P3.12 Resource indicators ───────────────────────────────────────────

    private const string Api = "https://api.example.com";

    [Fact]
    public async Task Resource_BecomesTheAccessTokenAudience_AndCanBeNarrowed()
    {
        await using var app = CreateApp(o =>
        {
            o.ResourceIndicatorsEnabled = true;
            o.AllowedResources = [Api, "https://other.example.com"];
        });
        await Oidc.SignInAsync(app, "alice");
        var authz = await Oidc.AuthorizeAsync(app,
            ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"), ("redirect_uri", Oidc.Callback),
            ("resource", Api), ("resource", "https://other.example.com"));

        var token = await RedeemAsync(app, Oidc.ResponseParams(authz)["code"]!, ("resource", Api));
        var at = Oidc.Jwt(JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("access_token").GetString()!);

        Assert.Contains(Api, at.Audiences);
        Assert.DoesNotContain("https://other.example.com", at.Audiences);
    }

    [Fact]
    public async Task Resource_NotAllowed_IsInvalidTarget()
    {
        await using var app = CreateApp(o => { o.ResourceIndicatorsEnabled = true; o.AllowedResources = [Api]; });
        await Oidc.SignInAsync(app, "alice");

        var resp = await AuthorizeCodeAsync(app, "test-client", ("resource", "https://evil.example.net"));

        Oidc.AssertRedirectError(resp, "invalid_target");
    }

    [Fact]
    public async Task Resource_NotAuthorized_CannotBeAddedAtTheTokenEndpoint()
    {
        await using var app = CreateApp(o => { o.ResourceIndicatorsEnabled = true; o.AllowedResources = [Api, "https://x.example.com"]; });
        await Oidc.SignInAsync(app, "alice");
        var authz = await AuthorizeCodeAsync(app, "test-client", ("resource", Api));

        var token = await RedeemAsync(app, Oidc.ResponseParams(authz)["code"]!, ("resource", "https://x.example.com"));

        await Oidc.AssertErrorAsync(token, HttpStatusCode.BadRequest, "invalid_target");
    }

    [Fact]
    public async Task ClientCredentials_ResourceIsValidated()
    {
        await using var app = CreateApp(o => { o.ResourceIndicatorsEnabled = true; o.AllowedResources = [Api]; });

        var ok = await Oidc.TokenAsync(app, [new("grant_type", "client_credentials"), new("resource", Api)], ("cc-client", "cc-secret"));
        var bad = await Oidc.TokenAsync(app, [new("grant_type", "client_credentials"), new("resource", "https://evil.example.net")], ("cc-client", "cc-secret"));

        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        await Oidc.AssertErrorAsync(bad, HttpStatusCode.BadRequest, "invalid_target");
    }

    // ── P3.13 FAPI ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Fapi2_TokenEndpoint_RequiresSenderConstrainedTokens()
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateApp(o =>
        {
            o.FapiProfile = FapiProfile.Fapi2Security;
            o.DPoPEnabled = true;
        }, PrivateKeyJwtClient(rsa, ["client_credentials"]));

        var resp = await Oidc.TokenAsync(app,
        [
            new("grant_type", "client_credentials"),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", Assertion(rsa)),
        ]);

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task Fapi2_Authorization_RequiresPar()
    {
        await using var app = CreateApp(o => o.FapiProfile = FapiProfile.Fapi2Security);
        await Oidc.SignInAsync(app, "alice");

        var resp = await AuthorizeCodeAsync(app, "test-client",
            ("code_challenge", Oidc.Challenge), ("code_challenge_method", "S256"));

        Oidc.AssertRedirectError(resp, "invalid_request");
    }

    [Fact]
    public async Task Fapi1_RejectsClientSecretJwt()
    {
        await using var app = CreateApp(o => o.FapiProfile = FapiProfile.Fapi1Advanced, new Client
        {
            ClientId = "hs",
            ClientSecret = new string('s', 64),
            TokenEndpointAuthMethod = "client_secret_jwt",
            AllowedGrantTypes = ["client_credentials"],
            AllowedScopes = ["openid"],
        });
        var assertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "hs",
            Audience = "https://auth.test.example.com/connect/token",
            Subject = new ClaimsIdentity([new Claim("sub", "hs")]),
            Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString() },
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(new string('s', 64))), SecurityAlgorithms.HmacSha256),
        });

        var resp = await Oidc.TokenAsync(app,
        [
            new("grant_type", "client_credentials"),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", assertion),
        ]);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string JwksFor(RSA rsa)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(false)));
        return JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", use = "sig", n = jwk.N, e = jwk.E } } });
    }

    private static Client JarClient(RSA rsa) => new()
    {
        ClientId = "jar-client",
        ClientSecret = "jar-secret",
        AllowedGrantTypes = ["authorization_code"],
        AllowedScopes = ["openid"],
        RedirectUris = [Oidc.Callback],
        RequirePkce = false,
        RequireConsent = false,
        JwksJson = JwksFor(rsa),
    };

    private static Client PrivateKeyJwtClient(RSA rsa, string[] grants) => new()
    {
        ClientId = "pkjwt",
        TokenEndpointAuthMethod = "private_key_jwt",
        AllowedGrantTypes = grants,
        AllowedScopes = ["openid"],
        JwksJson = JwksFor(rsa),
    };

    private static string RequestObject(RSA rsa, Dictionary<string, object> extra)
    {
        var claims = new Dictionary<string, object>
        {
            ["client_id"] = "jar-client",
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["redirect_uri"] = Oidc.Callback,
        };
        foreach (var kv in extra) claims[kv.Key] = kv.Value;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "jar-client",
            Audience = "https://auth.test.example.com",
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
        });
    }

    private static string Assertion(RSA rsa) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "pkjwt",
        Audience = "https://auth.test.example.com",
        Subject = new ClaimsIdentity([new Claim("sub", "pkjwt")]),
        Expires = DateTime.UtcNow.AddMinutes(2),
        Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString() },
        SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha256),
    });

    private static string DPoP(ECDsa key)
    {
        var p = key.ExportParameters(false);
        var jwk = JsonSerializer.Serialize(new
        {
            kty = "EC", crv = "P-256", x = Base64UrlEncoder.Encode(p.Q.X!), y = Base64UrlEncoder.Encode(p.Q.Y!),
        });
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString(),
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["htm"] = "POST",
                ["htu"] = "https://auth.test.example.com/connect/token",
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = JsonDocument.Parse(jwk).RootElement,
            },
        });
    }
}
