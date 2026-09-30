using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;
using NetOidc.Provider.Logout;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for defects found by the Phase 6 security review (REMEDIATION_PLAN P6.3).
/// Each test failed before its fix.
/// </summary>
public sealed class SecurityReviewTests
{
    private const string Issuer = "https://auth.test.example.com";

    // ── Expired client secrets (client_secret_expires_at) ───────────────────

    private static Client ExpiringClient(string prefix, string method, long expiresAt) => new()
    {
        ClientId = $"{prefix}-{method}",
        ClientSecret = "expiring-secret",
        TokenEndpointAuthMethod = method,
        ClientSecretExpiresAt = expiresAt,
        AllowedGrantTypes = ["client_credentials"],
        AllowedScopes = ["profile"],
    };

    [Theory]
    [InlineData("client_secret_basic")]
    [InlineData("client_secret_post")]
    public async Task ExpiredClientSecret_IsRejected(string method)
    {
        var past = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds();
        var future = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        await using var app = TestWebApp.Create(o => o.StaticClients =
        [
            .. o.StaticClients,
            ExpiringClient("expired", method, past),
            ExpiringClient("current", method, future),
        ]);

        Assert.Equal(HttpStatusCode.Unauthorized, (await SecretGrantAsync(app, method, $"expired-{method}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SecretGrantAsync(app, method, $"current-{method}")).StatusCode);
    }

    private static Task<HttpResponseMessage> SecretGrantAsync(TestWebApp app, string method, string clientId)
    {
        var form = new List<KeyValuePair<string, string>> { new("grant_type", "client_credentials"), new("scope", "profile") };
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token");
        if (method == "client_secret_basic")
            request.Headers.Authorization = Oidc.Basic(clientId, "expiring-secret");
        else
            form.AddRange([new("client_id", clientId), new("client_secret", "expiring-secret")]);
        request.Content = new FormUrlEncodedContent(form);
        return app.Client.SendAsync(request);
    }

    // ── FAPI 2.0: client assertion audience is the issuer only ──────────────

    public static TheoryData<object, HttpStatusCode> Fapi2Audiences => new()
    {
        { Issuer, HttpStatusCode.OK },
        { Issuer + "/connect/token", HttpStatusCode.Unauthorized },
        { new[] { Issuer }, HttpStatusCode.Unauthorized },
        { new[] { Issuer, "https://other.example.com" }, HttpStatusCode.Unauthorized },
    };

    [Theory]
    [MemberData(nameof(Fapi2Audiences))]
    public async Task Fapi2_ClientAssertionAudience_MustBeTheIssuerString(object audience, HttpStatusCode expected)
    {
        using var rsa = RSA.Create(2048);
        using var dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await using var app = TestWebApp.Create(o =>
        {
            o.FapiProfile = FapiProfile.Fapi2Security;
            o.DPoPEnabled = true;
            o.StaticClients = [.. o.StaticClients, PrivateKeyJwtClient(rsa)];
        });

        var assertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "pkjwt",
            Subject = new ClaimsIdentity([new Claim("sub", "pkjwt")]),
            Expires = DateTime.UtcNow.AddMinutes(1),
            Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString(), ["aud"] = audience },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha256),
        });

        var resp = await Oidc.TokenAsync(app,
        [
            new("grant_type", "client_credentials"),
            new("scope", "profile"),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", assertion),
        ], dpop: DPoPProof(dpopKey));

        Assert.True(resp.StatusCode == expected, $"{(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}");
    }

    // ── FAPI JOSE rules: PS256/ES256 only, request objects live ≤ 60 minutes ──

    private static TestWebApp CreateFapi1App(RSA rsa) => TestWebApp.Create(o =>
    {
        o.FapiProfile = FapiProfile.Fapi1Advanced;
        o.PushedAuthorizationEnabled = true;
        o.JarEnabled = true;
        o.JarmEnabled = true;
        var client = PrivateKeyJwtClient(rsa);
        o.StaticClients =
        [
            .. o.StaticClients,
            new Client
            {
                ClientId = client.ClientId,
                TokenEndpointAuthMethod = client.TokenEndpointAuthMethod,
                JwksJson = client.JwksJson,
                AllowedGrantTypes = ["authorization_code", "client_credentials"],
                AllowedScopes = ["openid", "profile"],
                RedirectUris = [Oidc.Callback],
                RequireConsent = false,
            },
        ];
    });

    private static string ClientAssertion(RSA rsa, string alg) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "pkjwt",
        Audience = Issuer,
        Subject = new ClaimsIdentity([new Claim("sub", "pkjwt")]),
        Expires = DateTime.UtcNow.AddMinutes(1),
        Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString() },
        SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), alg),
    });

    private static string RequestObject(RSA rsa, string alg, DateTime? notBefore, DateTime expires)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "pkjwt",
            Audience = Issuer,
            Expires = expires,
            Claims = new Dictionary<string, object>
            {
                ["client_id"] = "pkjwt",
                ["response_type"] = "code",
                ["response_mode"] = "jwt",
                ["scope"] = "openid",
                ["redirect_uri"] = Oidc.Callback,
                ["nonce"] = "n",
                ["state"] = "s",
                ["code_challenge"] = Oidc.Challenge,
                ["code_challenge_method"] = "S256",
            },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), alg),
        };
        if (notBefore is { } nbf)
            (descriptor.NotBefore, descriptor.IssuedAt) = (nbf, nbf);
        // Without defaults, nbf is only present when the test sets it.
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    public static TheoryData<string, int?, int, bool> FapiRequestObjects => new()
    {
        // alg, nbf offset (min), exp offset (min), accepted
        { SecurityAlgorithms.RsaSsaPssSha256, 0, 10, true },
        { SecurityAlgorithms.RsaSha256, 0, 10, false },          // RS256 is not permitted
        { SecurityAlgorithms.RsaSsaPssSha256, null, 10, false }, // nbf missing
        { SecurityAlgorithms.RsaSsaPssSha256, -70, 10, false },  // nbf more than 60 minutes old
        { SecurityAlgorithms.RsaSsaPssSha256, 0, 70, false },    // lifetime over 60 minutes
    };

    [Theory]
    [MemberData(nameof(FapiRequestObjects))]
    public async Task Fapi_RequestObjects_FollowTheProfileRules(string alg, int? nbfMinutes, int expMinutes, bool accepted)
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateFapi1App(rsa);
        var now = DateTime.UtcNow;
        var request = RequestObject(rsa, alg, nbfMinutes is { } n ? now.AddMinutes(n) : null, now.AddMinutes(expMinutes));

        var resp = await app.Client.PostAsync("/connect/par", new FormUrlEncodedContent(
        [
            new("client_id", "pkjwt"),
            new("request", request),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", ClientAssertion(rsa, SecurityAlgorithms.RsaSsaPssSha256)),
        ]));

        var body = await resp.Content.ReadAsStringAsync();
        if (accepted)
            Assert.True(resp.StatusCode == HttpStatusCode.Created, body);
        else
            await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request_object");
    }

    [Fact]
    public async Task Fapi_ClientAssertions_MustNotUseRs256()
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateFapi1App(rsa);

        Task<HttpResponseMessage> GrantAsync(string alg) => Oidc.TokenAsync(app,
        [
            new("grant_type", "client_credentials"),
            new("scope", "profile"),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", ClientAssertion(rsa, alg)),
        ]);

        Assert.Equal(HttpStatusCode.Unauthorized, (await GrantAsync(SecurityAlgorithms.RsaSha256)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await GrantAsync(SecurityAlgorithms.RsaSsaPssSha256)).StatusCode);
    }

    [Fact]
    public async Task Fapi_DPoPProofs_MustUsePs256OrEs256()
    {
        using var rsa = RSA.Create(2048);
        await using var app = TestWebApp.Create(o =>
        {
            o.FapiProfile = FapiProfile.Fapi2Security;
            o.DPoPEnabled = true;
            o.StaticClients = [.. o.StaticClients, PrivateKeyJwtClient(rsa)];
        });
        var discovery = JsonDocument.Parse(await app.Client.GetStringAsync("/.well-known/openid-configuration")).RootElement;
        Assert.Equal(["PS256", "ES256"], discovery.GetProperty("dpop_signing_alg_values_supported").EnumerateArray().Select(e => e.GetString()));

        async Task<HttpStatusCode> GrantAsync(string dpopAlg)
        {
            using var dpopKey = RSA.Create(2048);
            var p = dpopKey.ExportParameters(false);
            var proof = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Claims = new Dictionary<string, object>
                {
                    ["jti"] = Guid.NewGuid().ToString(), ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    ["htm"] = "POST", ["htu"] = Issuer + "/connect/token",
                },
                TokenType = "dpop+jwt",
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(dpopKey), dpopAlg),
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    ["jwk"] = new Dictionary<string, object>
                    {
                        ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(p.Modulus!), ["e"] = Base64UrlEncoder.Encode(p.Exponent!),
                    },
                },
            });
            var assertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "pkjwt",
                Audience = Issuer,
                Subject = new ClaimsIdentity([new Claim("sub", "pkjwt")]),
                Expires = DateTime.UtcNow.AddMinutes(1),
                Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString() },
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha256),
            });
            var resp = await Oidc.TokenAsync(app,
            [
                new("grant_type", "client_credentials"), new("scope", "profile"),
                new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", assertion),
            ], dpop: proof);
            return resp.StatusCode;
        }

        Assert.Equal(HttpStatusCode.BadRequest, await GrantAsync(SecurityAlgorithms.RsaSha256));
        Assert.Equal(HttpStatusCode.OK, await GrantAsync(SecurityAlgorithms.RsaSsaPssSha256));
    }

    [Theory]
    [InlineData(1024, "https://auth.test.example.com/connect/token", false)]   // weak key
    [InlineData(2048, "https://auth.test.example.com/connect/token", true)]
    [InlineData(2048, "https://AUTH.test.example.com/connect/token", true)]    // host is case-insensitive
    [InlineData(2048, "https://auth.test.example.com/connect/TOKEN", false)]   // path is not
    public async Task DPoPProofs_RequireStrongKeysAndAnExactPath(int keySize, string htu, bool accepted)
    {
        using var key = RSA.Create(keySize);
        var p = key.ExportParameters(false);
        var proof = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString(), ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["htm"] = "POST", ["htu"] = htu,
            },
            TokenType = "dpop+jwt",
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, object>
                {
                    ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(p.Modulus!), ["e"] = Base64UrlEncoder.Encode(p.Exponent!),
                },
            },
        });

        var thumbprint = await new DPoP.DPopProofValidator().ValidateProofAsync(proof, "POST", Issuer + "/connect/token");

        Assert.Equal(accepted, thumbprint is not null);
    }

    // ── Token type confusion ────────────────────────────────────────────────

    [Fact]
    public async Task AccessToken_IsNotAcceptedAsIdTokenSubjectToken()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.TokenExchangeEnabled = true;
            o.AuthorizeTokenExchange = (_, _) => Task.FromResult(true);
        });
        var tokens = await Oidc.CodeFlowAsync(app, clientId: "exchange-client", secret: "exchange-secret");

        Task<HttpResponseMessage> ExchangeAsync(string subjectToken) =>
            Oidc.TokenAsync(app,
            [
                new("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                new("subject_token", subjectToken),
                new("subject_token_type", "urn:ietf:params:oauth:token-type:id_token"),
            ], ("exchange-client", "exchange-secret"));

        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(tokens.GetProperty("id_token").GetString()!)).StatusCode);
        await Oidc.AssertErrorAsync(await ExchangeAsync(tokens.GetProperty("access_token").GetString()!),
            HttpStatusCode.BadRequest, "invalid_grant");
    }

    [Fact]
    public async Task AccessToken_IsNotAcceptedAsIdTokenHint()
    {
        await using var app = TestWebApp.Create();
        var tokens = await Oidc.CodeFlowAsync(app);
        var accessToken = tokens.GetProperty("access_token").GetString()!;

        // A valid hint for the signed-in user is accepted; an access token for the same user is not.
        var ok = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", Oidc.Callback), ("prompt", "none"), ("id_token_hint", tokens.GetProperty("id_token").GetString()!));
        var bad = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", Oidc.Callback), ("prompt", "none"), ("id_token_hint", accessToken));

        Assert.NotNull(Oidc.ResponseParams(ok)["code"]);
        Assert.Null(Oidc.ResponseParams(bad)["code"]);
    }

    // ── SSRF: outbound client and address classification ────────────────────

    [Theory]
    [InlineData("64:ff9b::a00:1", false)]        // NAT64 → 10.0.0.1
    [InlineData("64:ff9b::a9fe:a9fe", false)]    // NAT64 → 169.254.169.254
    [InlineData("64:ff9b::808:808", true)]       // NAT64 → 8.8.8.8
    [InlineData("2002:a00:1::1", false)]         // 6to4 → 10.0.0.1
    [InlineData("2002:808:808::1", true)]        // 6to4 → 8.8.8.8
    [InlineData("::a00:1", false)]               // IPv4-compatible → 10.0.0.1
    [InlineData("::ffff:127.0.0.1", false)]      // IPv4-mapped loopback
    [InlineData("2001:db8::1", false)]           // documentation
    [InlineData("2001:0:4136:e378::1", false)]   // Teredo
    [InlineData("100::1", false)]                // discard
    [InlineData("fd00::1", false)]               // unique-local
    [InlineData("2606:4700:4700::1111", true)]   // public
    [InlineData("93.184.216.34", true)]
    [InlineData("169.254.169.254", false)]
    public void AddressClassification(string address, bool isPublic) =>
        Assert.Equal(isPublic, NetworkAddressPolicy.IsPublic(System.Net.IPAddress.Parse(address)));

    [Fact]
    public async Task UntrustedHttpClient_BypassesConfiguredProxies()
    {
        await using var app = TestWebApp.Create();
        var handler = app.Services.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(BackChannelLogoutService.UntrustedHttpClientName);

        HttpMessageHandler? current = handler;
        while (current is DelegatingHandler d) current = d.InnerHandler;
        var sockets = Assert.IsType<SocketsHttpHandler>(current);

        Assert.False(sockets.UseProxy);
        Assert.False(sockets.AllowAutoRedirect);
        Assert.NotNull(sockets.ConnectCallback);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static Client PrivateKeyJwtClient(RSA rsa)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(false)));
        return new Client
        {
            ClientId = "pkjwt",
            TokenEndpointAuthMethod = "private_key_jwt",
            AllowedGrantTypes = ["client_credentials"],
            AllowedScopes = ["profile"],
            JwksJson = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", use = "sig", n = jwk.N, e = jwk.E } } }),
        };
    }

    private static string DPoPProof(ECDsa key)
    {
        var p = key.ExportParameters(false);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString(),
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["htm"] = "POST",
                ["htu"] = Issuer + "/connect/token",
            },
            TokenType = "dpop+jwt",
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, object>
                {
                    ["kty"] = "EC", ["crv"] = "P-256",
                    ["x"] = Base64UrlEncoder.Encode(p.Q.X!), ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
                },
            },
        });
    }
}
