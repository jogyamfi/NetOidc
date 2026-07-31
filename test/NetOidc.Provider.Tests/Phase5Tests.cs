using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.DPoP;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Integration tests for Phase 5: DPoP proof validation and binding,
/// private_key_jwt / client_secret_jwt auth, mTLS auth and certificate-bound tokens.
/// </summary>
public sealed class Phase5Tests
{
    // ── Helpers ────────────────────────────────────────────────────────────────

    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    /// <summary>Creates an ephemeral EC key pair for DPoP proofs.</summary>
    private static ECDsa CreateDPoPKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>
    /// Builds a DPoP proof JWT for the given key, method, and URI.
    /// Optionally includes an <c>ath</c> claim (for resource access proofs).
    /// </summary>
    private static string BuildDPoPProof(
        ECDsa key, string method, string uri,
        string? accessToken = null,
        DateTimeOffset? iat = null)
    {
        var now = iat ?? DateTimeOffset.UtcNow;
        var secKey = new ECDsaSecurityKey(key);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(secKey);
        // Strip private key material.
        var publicJwk = new JsonWebKey
        {
            Kty = jwk.Kty,
            Crv = jwk.Crv,
            X = jwk.X,
            Y = jwk.Y,
            Use = "sig",
        };
        var publicJwkJson = JsonSerializer.Serialize(new
        {
            kty = publicJwk.Kty,
            crv = publicJwk.Crv,
            x = publicJwk.X,
            y = publicJwk.Y,
        });

        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["htm"] = method,
            ["htu"] = uri,
        };
        if (accessToken is not null)
            claims["ath"] = DPopProofValidator.ComputeAth(accessToken);

        // Build the JWT with a custom header that includes the JWK.
        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(secKey, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = JsonDocument.Parse(publicJwkJson).RootElement,
            },
        };
        return handler.CreateToken(descriptor);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DPoP Tests (RFC 9449)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task DPoP_TokenEndpoint_IssuedWithCnfJkt_WhenProofIsValid()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DPoPEnabled = true;
        });

        var dpopKey = CreateDPoPKey();
        var tokenEndpoint = "https://auth.test.example.com/connect/token";
        var proof = BuildDPoPProof(dpopKey, "POST", tokenEndpoint);

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        };
        req.Headers.Add("DPoP", proof);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("DPoP", body.RootElement.GetProperty("token_type").GetString());

        // Verify the access token contains cnf.jkt
        var accessToken = body.RootElement.GetProperty("access_token").GetString()!;
        var jwt = new JsonWebToken(accessToken);
        Assert.True(jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnf));
        Assert.True(cnf.TryGetProperty("jkt", out _));
    }

    [Fact]
    public async Task DPoP_TokenEndpoint_Returns400_WhenDPoPDisabledButProofSent()
    {
        await using var app = TestWebApp.Create(); // DPoP not enabled

        var dpopKey = CreateDPoPKey();
        var proof = BuildDPoPProof(dpopKey, "POST", "https://auth.test.example.com/connect/token");

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        };
        req.Headers.Add("DPoP", proof);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task DPoP_TokenEndpoint_Returns400_WhenProofIsMalformed()
    {
        await using var app = TestWebApp.Create(opts => opts.DPoPEnabled = true);

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        };
        req.Headers.Add("DPoP", "not.a.valid.dpop.jwt");

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_dpop_proof", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task DPoP_TokenEndpoint_Returns400_WhenProofHasWrongHtm()
    {
        await using var app = TestWebApp.Create(opts => opts.DPoPEnabled = true);

        var dpopKey = CreateDPoPKey();
        // Wrong HTTP method (GET instead of POST)
        var proof = BuildDPoPProof(dpopKey, "GET", "https://auth.test.example.com/connect/token");

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        };
        req.Headers.Add("DPoP", proof);

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task DPoP_UserInfo_Returns200_WhenDPoPProofValid()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DPoPEnabled = true;
        });

        // Step 1: sign in
        await SignInAsync(app.Client, "dpop-user");

        var dpopKey = CreateDPoPKey();
        var tokenEndpoint = "https://auth.test.example.com/connect/token";

        // Step 2: get auth code
        var authResp = await app.Client.GetAsync(
            "/connect/authorize?response_type=code&client_id=test-client" +
            "&redirect_uri=https://client.test.example.com/callback&scope=openid+profile&state=s1");
        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var location = authResp.Headers.Location!.ToString();
        var code = System.Web.HttpUtility.ParseQueryString(
            new Uri(location).Query)["code"]!;

        // Step 3: exchange code for DPoP-bound token
        var tokenProof = BuildDPoPProof(dpopKey, "POST", tokenEndpoint);
        var tokenReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", "https://client.test.example.com/callback"),
            ]),
        };
        tokenReq.Headers.Add("DPoP", tokenProof);
        var tokenResp = await app.Client.SendAsync(tokenReq);
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.Equal("DPoP", tokenBody.RootElement.GetProperty("token_type").GetString());
        var accessToken = tokenBody.RootElement.GetProperty("access_token").GetString()!;

        // Step 4: call UserInfo with DPoP proof
        var userInfoEndpoint = "https://auth.test.example.com/connect/userinfo";
        var userInfoProof = BuildDPoPProof(dpopKey, "GET", userInfoEndpoint, accessToken: accessToken);
        var userInfoReq = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoReq.Headers.Authorization = AuthenticationHeaderValue.Parse($"DPoP {accessToken}");
        userInfoReq.Headers.Add("DPoP", userInfoProof);

        var userInfoResp = await app.Client.SendAsync(userInfoReq);
        Assert.Equal(HttpStatusCode.OK, userInfoResp.StatusCode);

        var userInfo = JsonDocument.Parse(await userInfoResp.Content.ReadAsStringAsync());
        Assert.Equal("dpop-user", userInfo.RootElement.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task DPoP_UserInfo_Returns401_WhenProofMissingForBoundToken()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DPoPEnabled = true;
        });

        await SignInAsync(app.Client, "dpop-user2");

        var dpopKey = CreateDPoPKey();
        var tokenEndpoint = "https://auth.test.example.com/connect/token";

        // Get auth code and exchange with DPoP
        var authResp = await app.Client.GetAsync(
            "/connect/authorize?response_type=code&client_id=test-client" +
            "&redirect_uri=https://client.test.example.com/callback&scope=openid&state=s2");
        var code = System.Web.HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;

        var tokenProof = BuildDPoPProof(dpopKey, "POST", tokenEndpoint);
        var tokenReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", "https://client.test.example.com/callback"),
            ]),
        };
        tokenReq.Headers.Add("DPoP", tokenProof);
        var tokenResp = await app.Client.SendAsync(tokenReq);
        var accessToken = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        // Try to call UserInfo with Bearer instead of DPoP — should fail
        var userInfoReq = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        // No DPoP header — the token has cnf.jkt so this should fail

        var userInfoResp = await app.Client.SendAsync(userInfoReq);
        Assert.Equal(HttpStatusCode.Unauthorized, userInfoResp.StatusCode);
    }

    [Fact]
    public async Task DPoP_Discovery_AdvertisesDPoPAlgorithms_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.DPoPEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        Assert.True(doc.RootElement.TryGetProperty("dpop_signing_alg_values_supported", out var algs));
        var algList = algs.EnumerateArray().Select(a => a.GetString()).ToList();
        Assert.Contains("ES256", algList);
        Assert.Contains("RS256", algList);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DPoP Proof Validator unit tests
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task DPoPProofValidator_AcceptsValidEcProof()
    {
        var validator = new DPopProofValidator();
        var key = CreateDPoPKey();
        var proof = BuildDPoPProof(key, "POST", "https://example.com/token");

        var thumbprint = await validator.ValidateProofAsync(proof, "POST", "https://example.com/token");
        Assert.NotNull(thumbprint);
    }

    [Fact]
    public async Task DPoPProofValidator_RejectsExpiredProof()
    {
        var validator = new DPopProofValidator();
        var key = CreateDPoPKey();
        var staleIat = DateTimeOffset.UtcNow.AddMinutes(-10);
        var proof = BuildDPoPProof(key, "POST", "https://example.com/token", iat: staleIat);

        var result = await validator.ValidateProofAsync(proof, "POST", "https://example.com/token",
            clockSkewSeconds: 60);
        Assert.Null(result);
    }

    [Fact]
    public async Task DPoPProofValidator_RejectsReplayedJti()
    {
        var validator = new DPopProofValidator();
        var key = CreateDPoPKey();
        var proof = BuildDPoPProof(key, "POST", "https://example.com/token");

        var first = await validator.ValidateProofAsync(proof, "POST", "https://example.com/token");
        Assert.NotNull(first);

        // Replay — same proof JWT
        var second = await validator.ValidateProofAsync(proof, "POST", "https://example.com/token");
        Assert.Null(second);
    }

    [Fact]
    public async Task DPoPProofValidator_RejectsWrongHtm()
    {
        var validator = new DPopProofValidator();
        var key = CreateDPoPKey();
        var proof = BuildDPoPProof(key, "POST", "https://example.com/token");

        var result = await validator.ValidateProofAsync(proof, "GET", "https://example.com/token");
        Assert.Null(result);
    }

    [Fact]
    public async Task DPoPProofValidator_ValidatesAth_WhenAccessTokenSupplied()
    {
        var validator = new DPopProofValidator();
        var key = CreateDPoPKey();
        var token = "some.access.token";
        var proof = BuildDPoPProof(key, "GET", "https://example.com/userinfo", accessToken: token);

        var result = await validator.ValidateProofAsync(
            proof, "GET", "https://example.com/userinfo", accessToken: token);
        Assert.NotNull(result);
    }

    [Fact]
    public async Task DPoPProofValidator_RejectsWrongAth()
    {
        var validator = new DPopProofValidator();
        var key = CreateDPoPKey();
        var proof = BuildDPoPProof(key, "GET", "https://example.com/userinfo",
            accessToken: "correct.token");

        var result = await validator.ValidateProofAsync(
            proof, "GET", "https://example.com/userinfo",
            accessToken: "wrong.token");
        Assert.Null(result);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // private_key_jwt client auth (RFC 7523 §2.2)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task PrivateKeyJwt_AuthenticatesClient_WhenAssertionIsValid()
    {
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportParameters(includePrivateParameters: true);
        var publicKey = rsa.ExportParameters(includePrivateParameters: false);
        var secKey = new RsaSecurityKey(privateKey);

        // Build inline JWKS with the public key only.
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(publicKey));
        var jwksJson = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", n = jwk.N, e = jwk.E, use = "sig" } } });

        await using var app = TestWebApp.Create(opts =>
        {
            opts.StaticClients = [
                .. opts.StaticClients,
                new Client
                {
                    ClientId = "pkjwt-client",
                    AllowedGrantTypes = ["client_credentials"],
                    AllowedScopes = ["profile"],
                    TokenEndpointAuthMethod = "private_key_jwt",
                    JwksJson = jwksJson,
                },
            ];
        });

        var assertion = BuildClientJwtAssertion(
            clientId: "pkjwt-client",
            audience: "https://auth.test.example.com/connect/token",
            signingKey: secKey,
            alg: SecurityAlgorithms.RsaSha256);

        var resp = await app.Client.PostAsync("/connect/token",
            new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
                new("client_id", "pkjwt-client"),
                new("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", assertion),
            ]));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task PrivateKeyJwt_Returns401_WhenSignatureIsWrong()
    {
        using var correctRsa = RSA.Create(2048);
        using var wrongRsa = RSA.Create(2048);   // different key — wrong signature

        var publicKey = correctRsa.ExportParameters(includePrivateParameters: false);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(publicKey));
        var jwksJson = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", n = jwk.N, e = jwk.E, use = "sig" } } });

        await using var app = TestWebApp.Create(opts =>
        {
            opts.StaticClients = [
                .. opts.StaticClients,
                new Client
                {
                    ClientId = "pkjwt-wrong-client",
                    AllowedGrantTypes = ["client_credentials"],
                    AllowedScopes = ["profile"],
                    TokenEndpointAuthMethod = "private_key_jwt",
                    JwksJson = jwksJson,
                },
            ];
        });

        var wrongKey = new RsaSecurityKey(wrongRsa.ExportParameters(includePrivateParameters: true));
        var assertion = BuildClientJwtAssertion(
            "pkjwt-wrong-client",
            "https://auth.test.example.com/connect/token",
            wrongKey,
            SecurityAlgorithms.RsaSha256);

        var resp = await app.Client.PostAsync("/connect/token",
            new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
                new("client_id", "pkjwt-wrong-client"),
                new("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", assertion),
            ]));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // client_secret_jwt client auth (RFC 7523 §2.3)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ClientSecretJwt_AuthenticatesClient_WhenAssertionIsValid()
    {
        const string secret = "a-very-long-shared-secret-for-hs256-signing!";

        await using var app = TestWebApp.Create(opts =>
        {
            opts.StaticClients = [
                .. opts.StaticClients,
                new Client
                {
                    ClientId = "csjwt-client",
                    ClientSecret = secret,
                    AllowedGrantTypes = ["client_credentials"],
                    AllowedScopes = ["profile"],
                    TokenEndpointAuthMethod = "client_secret_jwt",
                },
            ];
        });

        var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var assertion = BuildClientJwtAssertion(
            "csjwt-client",
            "https://auth.test.example.com/connect/token",
            secretKey,
            SecurityAlgorithms.HmacSha256);

        var resp = await app.Client.PostAsync("/connect/token",
            new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
                new("client_id", "csjwt-client"),
                new("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", assertion),
            ]));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // mTLS client auth (RFC 8705) and certificate-bound tokens
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Mtls_TlsClientAuth_AuthenticatesClient_BySubjectDn()
    {
        var (cert, _) = CreateSelfSignedCert("CN=mtls-test-client");
        var certPem = cert.ExportCertificatePem();

        await using var app = TestWebApp.Create(opts =>
        {
            opts.MtlsEnabled = true;
            opts.MtlsClientCertificateHeader = "X-Client-Cert";

            opts.StaticClients = [
                .. opts.StaticClients,
                new Client
                {
                    ClientId = "mtls-client",
                    AllowedGrantTypes = ["client_credentials"],
                    AllowedScopes = ["profile"],
                    TokenEndpointAuthMethod = "tls_client_auth",
                    TlsClientAuthSubjectDn = "CN=mtls-test-client",
                    UseMtlsBoundTokens = true,
                },
            ];
        });

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
                new("client_id", "mtls-client"),
            ]),
        };
        req.Headers.Add("X-Client-Cert", Uri.EscapeDataString(certPem));

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var accessToken = body.RootElement.GetProperty("access_token").GetString()!;

        // Verify the token contains cnf.x5t#S256
        var jwt = new JsonWebToken(accessToken);
        Assert.True(jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnf));
        Assert.True(cnf.TryGetProperty("x5t#S256", out _));
    }

    [Fact]
    public async Task Mtls_Discovery_AdvertisesTlsClientCertBoundTokens_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.MtlsEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        Assert.True(doc.RootElement.GetProperty("tls_client_certificate_bound_access_tokens").GetBoolean());

        var authMethods = doc.RootElement
            .GetProperty("token_endpoint_auth_methods_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();
        Assert.Contains("tls_client_auth", authMethods);
        Assert.Contains("self_signed_tls_client_auth", authMethods);
    }

    [Fact]
    public async Task Mtls_SelfSignedTlsClientAuth_AuthenticatesClient_ByPublicKeyInJwks()
    {
        var (cert, rsaKey) = CreateSelfSignedCert("CN=self-signed-client");
        var certPem = cert.ExportCertificatePem();

        var pubParams = rsaKey.ExportParameters(false);
        var jwk = new { kty = "RSA", n = Base64UrlEncoder.Encode(pubParams.Modulus!), e = Base64UrlEncoder.Encode(pubParams.Exponent!), use = "sig" };
        var jwksJson = JsonSerializer.Serialize(new { keys = new[] { jwk } });

        await using var app = TestWebApp.Create(opts =>
        {
            opts.MtlsEnabled = true;
            opts.MtlsClientCertificateHeader = "X-Client-Cert";

            opts.StaticClients = [
                .. opts.StaticClients,
                new Client
                {
                    ClientId = "ss-mtls-client",
                    AllowedGrantTypes = ["client_credentials"],
                    AllowedScopes = ["profile"],
                    TokenEndpointAuthMethod = "self_signed_tls_client_auth",
                    JwksJson = jwksJson,
                },
            ];
        });

        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
                new("client_id", "ss-mtls-client"),
            ]),
        };
        req.Headers.Add("X-Client-Cert", Uri.EscapeDataString(certPem));

        var resp = await app.Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Private helpers
    // ═══════════════════════════════════════════════════════════════════════════

    private static string BuildClientJwtAssertion(
        string clientId, string audience, SecurityKey signingKey, string alg)
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTime.UtcNow;
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Subject = new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("sub", clientId),
            ]),
            Audience = audience,
            IssuedAt = now,
            Expires = now.AddMinutes(2),
            Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString() },
            SigningCredentials = new SigningCredentials(signingKey, alg),
        });
    }

    /// <summary>Creates a self-signed RSA certificate with the given subject DN.</summary>
    private static (X509Certificate2 Cert, RSA Key) CreateSelfSignedCert(string subjectName)
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return (cert, rsa);
    }
}
