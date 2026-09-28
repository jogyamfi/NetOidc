using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P2.1 (client assertions, single auth method) and
/// P2.2 (mTLS certificate sourcing and matching).
/// </summary>
public sealed class ClientAuthSecurityTests : IDisposable
{
    private const string TokenEndpoint = "https://auth.test.example.com/connect/token";
    private readonly RSA _clientKey = RSA.Create(2048);

    public void Dispose() => _clientKey.Dispose();

    // ── P2.1 private_key_jwt ─────────────────────────────────────────────────

    [Fact]
    public async Task ValidAssertion_Authenticates()
    {
        await using var app = CreateApp();
        var resp = await AssertionGrantAsync(app, Assertion());
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Assertion_WithSubjectDifferentFromIssuer_IsRejected()
    {
        await using var app = CreateApp();
        var resp = await AssertionGrantAsync(app, Assertion(sub: "someone-else"));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ReplayedAssertion_IsRejected()
    {
        await using var app = CreateApp();
        var assertion = Assertion();

        Assert.Equal(HttpStatusCode.OK, (await AssertionGrantAsync(app, assertion)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await AssertionGrantAsync(app, assertion)).StatusCode);
    }

    [Fact]
    public async Task Assertion_WithoutJti_IsRejected()
    {
        await using var app = CreateApp();
        var resp = await AssertionGrantAsync(app, Assertion(jti: null));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task LongLivedAssertion_IsRejected()
    {
        await using var app = CreateApp();
        var resp = await AssertionGrantAsync(app, Assertion(lifetime: TimeSpan.FromHours(1)));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task HmacSignedAssertion_ForPrivateKeyJwtClient_IsRejected()
    {
        await using var app = CreateApp();
        var hmac = new SigningCredentials(
            new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)), SecurityAlgorithms.HmacSha256);
        var resp = await AssertionGrantAsync(app, Assertion(signing: hmac));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── P2.1 client_secret_jwt ───────────────────────────────────────────────

    [Fact]
    public async Task ClientSecretJwt_UsesRawSecret()
    {
        const string secret = "a-raw-shared-secret-that-is-at-least-32-bytes";
        await using var app = CreateApp(secretJwtSecret: secret);
        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)), SecurityAlgorithms.HmacSha256);

        var resp = await AssertionGrantAsync(app, Assertion(clientId: "hs-client", signing: creds));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ClientSecretJwt_WithSecretShorterThanHash_IsRejected()
    {
        const string secret = "only-16-bytes!!!";
        await using var app = CreateApp(secretJwtSecret: secret);
        // Pad the key for signing; the server must refuse because the registered secret is too short.
        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret.PadRight(32, '\0'))), SecurityAlgorithms.HmacSha256);

        var resp = await AssertionGrantAsync(app, Assertion(clientId: "hs-client", signing: creds));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── P2.1 single authentication method ────────────────────────────────────

    [Fact]
    public async Task BasicAuthPlusFormSecret_IsRejected()
    {
        await using var app = CreateApp();
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic("cc-client", "cc-secret") },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("client_secret", "cc-secret"),
            ]),
        });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task BasicAuthWithDifferentFormClientId_IsRejected()
    {
        await using var app = CreateApp();
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic("cc-client", "cc-secret") },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("client_id", "test-client"),
            ]),
        });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── P2.2 mTLS ────────────────────────────────────────────────────────────

    [Fact]
    public async Task CertificateHeader_FromUntrustedPeer_IsIgnored()
    {
        using var cert = SelfSigned("CN=mtls-client");
        await using var app = CreateMtlsApp(cert);

        var resp = await MtlsGrantAsync(app, cert, remoteIp: "203.0.113.7");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task CertificateHeader_FromTrustedProxy_Authenticates()
    {
        using var cert = SelfSigned("CN=mtls-client");
        await using var app = CreateMtlsApp(cert);

        var resp = await MtlsGrantAsync(app, cert);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task TlsClientAuth_CertificateNotChainingToTrustAnchor_IsRejected()
    {
        using var trusted = SelfSigned("CN=some-ca");
        using var cert = SelfSigned("CN=mtls-client");
        await using var app = CreateMtlsApp(trustAnchor: trusted);

        var resp = await MtlsGrantAsync(app, cert);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task SecretClient_PresentingCertificate_CanStillUseClientSecretPost()
    {
        using var cert = SelfSigned("CN=unrelated");
        await using var app = CreateMtlsApp(cert);
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("client_id", "post-client"),
                new("client_secret", "post-secret"),
            ]),
        };
        req.Headers.Add("X-Client-Cert", Uri.EscapeDataString(cert.ExportCertificatePem()));

        var resp = await app.Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Theory]
    [InlineData("CN=mtls-client, O=Example Org", true)]
    [InlineData("cn=MTLS-CLIENT,o=example   org", true)]
    [InlineData("O=Example Org, CN=mtls-client", false)]   // order is significant
    [InlineData("CN=mtls-client", false)]                  // missing attribute
    [InlineData("CN=mtls-client, O=Other Org", false)]
    public void SubjectDn_IsComparedPerRfc4514(string configured, bool expected)
    {
        using var cert = SelfSigned("CN=mtls-client, O=Example Org");
        Assert.Equal(expected, ClientAuthenticator.SubjectDnMatches(cert, configured));
    }

    [Fact]
    public void AllSanUris_AreConsidered()
    {
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri("https://first.example.com/client"));
        san.AddDnsName("client.example.com");
        san.AddUri(new Uri("spiffe://example.org/workload"));
        using var cert = SelfSigned("CN=san", san.Build());

        var uris = ClientAuthenticator.SanValues(cert, 6).ToList();

        Assert.Equal(["https://first.example.com/client", "spiffe://example.org/workload"], uris);
        Assert.Equal(["client.example.com"], ClientAuthenticator.SanValues(cert, 2));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private TestWebApp CreateApp(string? secretJwtSecret = null)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new RsaSecurityKey(_clientKey.ExportParameters(false)) { KeyId = "k1" });
        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[] { new { kty = "RSA", use = "sig", kid = "k1", n = jwk.N, e = jwk.E } },
        });

        return TestWebApp.Create(o => o.StaticClients =
        [
            .. o.StaticClients,
            new Client
            {
                ClientId = "pkjwt-client",
                TokenEndpointAuthMethod = "private_key_jwt",
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
                JwksJson = jwks,
            },
            new Client
            {
                ClientId = "hs-client",
                ClientSecret = secretJwtSecret ?? "unused-secret-unused-secret-unused-secret",
                TokenEndpointAuthMethod = "client_secret_jwt",
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
            },
        ]);
    }

    private string Assertion(
        string clientId = "pkjwt-client", string? sub = null, string? jti = "default",
        TimeSpan? lifetime = null, SigningCredentials? signing = null)
    {
        var claims = new Dictionary<string, object> { ["sub"] = sub ?? clientId };
        if (jti is not null) claims["jti"] = jti == "default" ? Guid.NewGuid().ToString() : jti;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = TokenEndpoint,
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow + (lifetime ?? TimeSpan.FromMinutes(2)),
            Claims = claims,
            SigningCredentials = signing ?? new SigningCredentials(
                new RsaSecurityKey(_clientKey) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256),
        });
    }

    private static Task<HttpResponseMessage> AssertionGrantAsync(TestWebApp app, string assertion) =>
        app.Client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("scope", "profile"),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", assertion),
        ]));

    private static TestWebApp CreateMtlsApp(X509Certificate2? trustAnchor) => TestWebApp.Create(o =>
    {
        o.MtlsEnabled = true;
        o.MtlsClientCertificateHeader = "X-Client-Cert";
        if (trustAnchor is not null) o.MtlsCertificateAuthorities = [trustAnchor];
        o.StaticClients =
        [
            .. o.StaticClients,
            new Client
            {
                ClientId = "mtls-client",
                TokenEndpointAuthMethod = "tls_client_auth",
                TlsClientAuthSubjectDn = "CN=mtls-client",
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
            },
            new Client
            {
                ClientId = "post-client",
                ClientSecret = "post-secret",
                TokenEndpointAuthMethod = "client_secret_post",
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
            },
        ];
    });

    private static Task<HttpResponseMessage> MtlsGrantAsync(TestWebApp app, X509Certificate2 cert, string? remoteIp = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("client_id", "mtls-client"),
                new("scope", "profile"),
            ]),
        };
        req.Headers.Add("X-Client-Cert", Uri.EscapeDataString(cert.ExportCertificatePem()));
        if (remoteIp is not null) req.Headers.Add("X-Test-Remote-Ip", remoteIp);
        return app.Client.SendAsync(req);
    }

    private static X509Certificate2 SelfSigned(string subject, X509Extension? extension = null)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (extension is not null) request.CertificateExtensions.Add(extension);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static AuthenticationHeaderValue Basic(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));
}
