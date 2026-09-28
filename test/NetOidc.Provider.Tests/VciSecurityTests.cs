using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Vci;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P1.5 (OID4VCI proof and token checks).</summary>
public sealed class VciSecurityTests
{
    private const string Issuer = "https://auth.test.example.com";

    [Fact]
    public async Task ValidProof_IssuesCredential_BoundToProvenKey()
    {
        CredentialIssuanceRequest? seen = null;
        await using var app = CreateApp(onIssue: r => seen = r);
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, await UserTokenAsync(app),
            Proof(holder, await NonceAsync(app)));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.NotNull(seen);
        Assert.Equal("alice", seen!.Subject);
        var jwk = new JsonWebKey(Assert.Single(seen.HolderPublicJwks));
        Assert.Equal(Base64UrlEncoder.Encode(holder.ExportParameters(false).Q.X!), jwk.X);
    }

    [Fact]
    public async Task ProofSignedByDifferentKey_IsRejected()
    {
        await using var app = CreateApp();
        using var claimed = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, await UserTokenAsync(app),
            Proof(attacker, await NonceAsync(app), headerKey: claimed));

        await AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_proof");
    }

    [Fact]
    public async Task ProofWithoutNonce_IsRejected()
    {
        await using var app = CreateApp();
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, await UserTokenAsync(app), Proof(holder, nonce: null));

        await AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_nonce");
    }

    [Fact]
    public async Task ReplayedProof_IsRejected()
    {
        await using var app = CreateApp();
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = await UserTokenAsync(app);
        var proof = Proof(holder, await NonceAsync(app));

        Assert.Equal(HttpStatusCode.OK, (await RequestCredentialAsync(app, token, proof)).StatusCode);
        await AssertErrorAsync(await RequestCredentialAsync(app, token, proof),
            HttpStatusCode.BadRequest, "invalid_nonce");
    }

    [Fact]
    public async Task MissingProof_WhenBindingRequired_IsRejected()
    {
        await using var app = CreateApp();

        var resp = await RequestCredentialAsync(app, await UserTokenAsync(app), proofJwt: null);

        await AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_proof");
    }

    [Fact]
    public async Task ProofCarryingPrivateKey_IsRejected()
    {
        await using var app = CreateApp();
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, await UserTokenAsync(app),
            Proof(holder, await NonceAsync(app), includePrivateKey: true));

        await AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_proof");
    }

    [Fact]
    public async Task BatchProofs_AreAllVerified()
    {
        CredentialIssuanceRequest? seen = null;
        await using var app = CreateApp(onIssue: r => seen = r);
        using var k1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var k2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proofs = new[] { Proof(k1, await NonceAsync(app)), Proof(k2, await NonceAsync(app)) };

        var resp = await PostAsync(app, await UserTokenAsync(app),
            JsonSerializer.Serialize(new { credential_configuration_id = "Degree", proofs = new { jwt = proofs } }));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(2, seen!.HolderPublicJwks.Count);
    }

    [Fact]
    public async Task ClientCredentialsToken_WithoutSubject_IsRejected()
    {
        await using var app = CreateApp();
        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("cc-client:cc-secret"))) },
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials"), new("scope", "profile")]),
        });
        var ccToken = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, ccToken, Proof(holder, await NonceAsync(app)));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task RevokedAccessToken_IsRejected()
    {
        await using var app = CreateApp();
        var token = await UserTokenAsync(app);
        var jti = new JsonWebToken(token).Id;
        await app.Services.GetRequiredService<IAdapter<AccessToken>>().RemoveAsync(jti);
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, token, Proof(holder, await NonceAsync(app)));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task TokenWithoutConfigurationScope_IsRejected()
    {
        await using var app = CreateApp();
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "openid");
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, token, Proof(holder, await NonceAsync(app)));

        await AssertErrorAsync(resp, HttpStatusCode.Forbidden, "insufficient_scope");
    }

    [Fact]
    public async Task IssuerHookException_IsNotEchoed()
    {
        await using var app = CreateApp(onIssue: _ => throw new InvalidOperationException("db password=hunter2"));
        using var holder = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var resp = await RequestCredentialAsync(app, await UserTokenAsync(app), Proof(holder, await NonceAsync(app)));

        Assert.Equal(HttpStatusCode.InternalServerError, resp.StatusCode);
        Assert.DoesNotContain("hunter2", await resp.Content.ReadAsStringAsync());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static TestWebApp CreateApp(Action<CredentialIssuanceRequest>? onIssue = null) =>
        TestWebApp.Create(o =>
        {
            o.VciEnabled = true;
            o.Scopes = [.. o.Scopes, new Scope { Name = "Degree" }];
            o.VciCredentialConfigurations.Add(new CredentialConfiguration
            {
                Id = "Degree",
                Format = "jwt_vc_json",
                Scope = "Degree",
            });
            o.IssueCredential = (req, _) =>
            {
                onIssue?.Invoke(req);
                return Task.FromResult("issued-credential");
            };
        });

    private static Task<string> UserTokenAsync(TestWebApp app) =>
        app.IssueUserAccessTokenAsync("alice", "test-client", "openid", "Degree");

    private static async Task<string> NonceAsync(TestWebApp app)
    {
        var resp = await app.Client.PostAsync("/connect/nonce", content: null);
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("c_nonce").GetString()!;
    }

    private static string Proof(ECDsa signer, string? nonce, ECDsa? headerKey = null, bool includePrivateKey = false)
    {
        var p = (headerKey ?? signer).ExportParameters(includePrivateKey);
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(p.Q.X!),
            ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
        };
        if (includePrivateKey) jwk["d"] = Base64UrlEncoder.Encode(p.D!);

        var claims = new Dictionary<string, object>();
        if (nonce is not null) claims["nonce"] = nonce;

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = Issuer,
            IssuedAt = DateTime.UtcNow,
            TokenType = "openid4vci-proof+jwt",
            Claims = claims,
            AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwk },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(signer), SecurityAlgorithms.EcdsaSha256),
        });
    }

    private static Task<HttpResponseMessage> RequestCredentialAsync(TestWebApp app, string token, string? proofJwt) =>
        PostAsync(app, token, proofJwt is null
            ? """{"credential_configuration_id":"Degree"}"""
            : JsonSerializer.Serialize(new
            {
                credential_configuration_id = "Degree",
                proof = new { proof_type = "jwt", jwt = proofJwt },
            }));

    private static Task<HttpResponseMessage> PostAsync(TestWebApp app, string token, string json) =>
        app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/credential")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) },
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        });

    private static async Task AssertErrorAsync(HttpResponseMessage resp, HttpStatusCode status, string error)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == status, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal(error, JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }
}
