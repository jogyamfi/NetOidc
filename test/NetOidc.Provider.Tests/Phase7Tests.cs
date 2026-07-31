using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Tests for Phase 7: FAPI 1.0 Advanced, FAPI 2.0 Security Profile,
/// FAPI 2.0 Message Signing, and FAPI-CIBA profile enforcement.
/// </summary>
public sealed class Phase7Tests
{
    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    // ═══════════════════════════════════════════════════════════════════════════
    // FapiProfileValidator unit tests
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Validator_Returns_Skip_WhenProfileIsNone()
    {
        var validator = new FapiProfileValidator();
        var opts = new ProviderOptions { FapiProfile = FapiProfile.None, FapiProfileValidationEnabled = true };

        var result = validator.Validate(null, opts);

        Assert.Equal(ValidateOptionsResult.Skip, result);
    }

    [Fact]
    public void Validator_Returns_Skip_WhenValidationDisabled()
    {
        var validator = new FapiProfileValidator();
        var opts = new ProviderOptions { FapiProfile = FapiProfile.Fapi2Security, FapiProfileValidationEnabled = false };

        var result = validator.Validate(null, opts);

        Assert.Equal(ValidateOptionsResult.Skip, result);
    }

    [Fact]
    public void Validator_Fapi2_Fails_WhenSenderConstrainedNotEnabled()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.DPoPEnabled = false;
        opts.MtlsEnabled = false;

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("sender-constrained"));
    }

    [Fact]
    public void Validator_Fapi2_Fails_WhenPARNotRequired()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.RequirePushedAuthorization = false;

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("RequirePushedAuthorization"));
    }

    [Fact]
    public void Validator_Fapi2_Fails_WhenAuthCodeLifetimeTooLong()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.AuthorizationCodeLifetimeSeconds = 120;

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("AuthorizationCodeLifetimeSeconds"));
    }

    [Fact]
    public void Validator_Fapi2_Fails_WhenIssuerIdentificationDisabled()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.IssuerIdentificationEnabled = false;

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("IssuerIdentificationEnabled"));
    }

    [Fact]
    public void Validator_Fapi2_Fails_WhenClientUsesNonCompliantAuthMethod()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.StaticClients =
        [
            new Client
            {
                ClientId = "bad-client",
                AllowedGrantTypes = ["authorization_code"],
                AllowedScopes = ["openid"],
                TokenEndpointAuthMethod = "client_secret_basic",
            },
        ];

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("bad-client") && f.Contains("client_secret_basic"));
    }

    [Fact]
    public void Validator_Fapi2_Passes_WhenAllConstraintsMet()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();

        var result = validator.Validate(null, opts);

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validator_Fapi1_Fails_WhenClientUsesClientSecretBasic()
    {
        var validator = new FapiProfileValidator();
        var opts = new ProviderOptions
        {
            FapiProfile = FapiProfile.Fapi1Advanced,
            FapiProfileValidationEnabled = true,
            StaticClients =
            [
                new Client
                {
                    ClientId = "fapi1-bad",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                },
            ],
        };

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("fapi1-bad") && f.Contains("client_secret_basic"));
    }

    [Fact]
    public void Validator_Fapi1_Passes_WhenClientsUseAllowedMethods()
    {
        var validator = new FapiProfileValidator();
        var opts = new ProviderOptions
        {
            FapiProfile = FapiProfile.Fapi1Advanced,
            FapiProfileValidationEnabled = true,
            StaticClients =
            [
                new Client
                {
                    ClientId = "fapi1-pkjwt",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    TokenEndpointAuthMethod = "private_key_jwt",
                },
            ],
        };

        var result = validator.Validate(null, opts);

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validator_FapiMessageSigning_Fails_WhenJarmOrJarDisabled()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.FapiProfile = FapiProfile.Fapi2MessageSigning;
        // JarmEnabled and JarEnabled are false by default.

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("JarmEnabled"));
        Assert.Contains(result.Failures, f => f.Contains("JarEnabled"));
    }

    [Fact]
    public void Validator_FapiMessageSigning_Passes_WhenJarmAndJarEnabled()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.FapiProfile = FapiProfile.Fapi2MessageSigning;
        opts.JarmEnabled = true;
        opts.JarEnabled = true;

        var result = validator.Validate(null, opts);

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validator_FapiCiba_Fails_WhenCibaDisabled()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.FapiProfile = FapiProfile.FapiCiba;
        opts.CibaEnabled = false;

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("CibaEnabled"));
    }

    [Fact]
    public void Validator_Fapi2_Fails_WhenParLifetimeTooLong()
    {
        var validator = new FapiProfileValidator();
        var opts = BuildFapi2CompliantOptions();
        opts.PushedAuthorizationLifetimeSeconds = 601;

        var result = validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("PushedAuthorizationLifetimeSeconds"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // UseFapiProfile() builder extension
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void UseFapiProfile_Sets_Profile_And_ValidationFlag()
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        // Use validate:false so IOptions<T>.Value doesn't throw during this structural test.
        services.AddNetOidc(o => o.Issuer = "https://test.example.com")
                .UseFapiProfile(FapiProfile.Fapi2Security, validate: false);

        var sp = services.BuildServiceProvider();
        var resolved = sp.GetRequiredService<IOptions<ProviderOptions>>().Value;

        Assert.Equal(FapiProfile.Fapi2Security, resolved.FapiProfile);
        Assert.False(resolved.FapiProfileValidationEnabled);
    }

    [Fact]
    public void UseFapiProfile_Enables_ValidationFlag_WhenRequested()
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        // Configure a FAPI 2.0 compliant setup so validation passes.
        services.AddNetOidc(o =>
        {
            o.Issuer = "https://test.example.com";
            o.DPoPEnabled = true;
            o.RequirePushedAuthorization = true;
            o.PushedAuthorizationEnabled = true;
            o.PushedAuthorizationLifetimeSeconds = 90;
            o.AuthorizationCodeLifetimeSeconds = 60;
            o.IssuerIdentificationEnabled = true;
        }).UseFapiProfile(FapiProfile.Fapi2Security, validate: true);

        var sp = services.BuildServiceProvider();
        var resolved = sp.GetRequiredService<IOptions<ProviderOptions>>().Value;

        Assert.Equal(FapiProfile.Fapi2Security, resolved.FapiProfile);
        Assert.True(resolved.FapiProfileValidationEnabled);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FAPI 1.0 Advanced — authorization endpoint runtime enforcement
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Fapi1_Authorization_Rejects_ImplicitResponseType()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi1Advanced;
            opts.JarmEnabled = true;
        });

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=implicit-client&response_type=token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("FAPI 1.0", Uri.UnescapeDataString(location));
    }

    [Fact]
    public async Task Fapi1_Authorization_Rejects_Code_WhenJarmNotUsed()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi1Advanced;
            opts.JarmEnabled = true;
        });

        // response_mode=query (not jwt) should be rejected for FAPI 1.0 code flow.
        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1&response_mode=query");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("FAPI 1.0", Uri.UnescapeDataString(location));
    }

    [Fact]
    public async Task Fapi1_Authorization_Rejects_OpenId_WhenNonceMissing()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi1Advanced;
            opts.JarmEnabled = true;
        });

        // response_mode=query.jwt to satisfy JARM, but no nonce.
        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&response_mode=query.jwt");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("nonce", Uri.UnescapeDataString(location));
    }

    [Fact]
    public async Task Fapi1_Authorization_Allows_CodeIdToken_HybridFlow()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi1Advanced;
            opts.JarmEnabled = true;
        });
        await SignInAsync(app.Client, "alice");

        // code+id_token hybrid is explicitly allowed by FAPI 1.0.
        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=hybrid-client" +
            "&response_type=code%20id_token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        // Should contain code and id_token in fragment, not an error.
        Assert.DoesNotContain("error=", location);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FAPI 2.0 Security Profile — authorization endpoint runtime enforcement
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Fapi2_Authorization_Rejects_ImplicitResponseType()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi2Security;
        });

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=implicit-client&response_type=token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("FAPI 2.0", Uri.UnescapeDataString(location));
    }

    [Fact]
    public async Task Fapi2_Authorization_Rejects_HybridResponseType()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi2Security;
        });

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=hybrid-client" +
            "&response_type=code%20id_token" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("FAPI 2.0", Uri.UnescapeDataString(location));
    }

    [Fact]
    public async Task Fapi2_Authorization_Rejects_Code_WhenCodeChallengeAbsent()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi2Security;
        });

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("code_challenge", Uri.UnescapeDataString(location));
    }

    [Fact]
    public async Task Fapi2_Authorization_Rejects_Code_WhenPlainPkceUsed()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi2Security;
        });

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&nonce=n1" +
            "&code_challenge=some_challenge&code_challenge_method=plain");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("S256", Uri.UnescapeDataString(location));
    }

    [Fact]
    public async Task Fapi2_Authorization_Allows_Code_WithS256Pkce()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi2Security;
        });
        await SignInAsync(app.Client, "fapi2-user");

        var verifier = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var challengeBytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(challengeBytes)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            $"&scope=openid&nonce=n1&code_challenge={challenge}&code_challenge_method=S256");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        // Should redirect to callback with code, not an error.
        Assert.DoesNotContain("error=", location);
        Assert.Contains("code=", location);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FAPI 1.0 — PAR endpoint enforcement
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Fapi1_Par_Rejects_WhenCodeChallengeAbsent()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportParameters(includePrivateParameters: false);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(publicKey));
        var jwksJson = JsonSerializer.Serialize(
            new { keys = new[] { new { kty = "RSA", n = jwk.N, e = jwk.E, use = "sig" } } });

        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi1Advanced;
            opts.PushedAuthorizationEnabled = true;
            opts.JarmEnabled = true;
            opts.StaticClients = [
                .. opts.StaticClients,
                new Client
                {
                    ClientId = "fapi1-par-client",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "private_key_jwt",
                    JwksJson = jwksJson,
                },
            ];
        });

        var signingKey = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: true));
        var assertion = BuildClientJwtAssertion(
            "fapi1-par-client",
            "https://auth.test.example.com/connect/par",
            signingKey,
            SecurityAlgorithms.RsaSha256);

        var resp = await app.Client.PostAsync("/connect/par",
            new FormUrlEncodedContent(
            [
                new("client_id", "fapi1-par-client"),
                new("response_type", "code"),
                new("redirect_uri", "https://client.test.example.com/callback"),
                new("scope", "openid"),
                new("nonce", "test-nonce"),
                new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", assertion),
                // No code_challenge — should fail FAPI 1.0 PAR check.
            ]));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", body.RootElement.GetProperty("error").GetString());
        Assert.Contains("code_challenge",
            body.RootElement.GetProperty("error_description").GetString()!);
    }

    [Fact]
    public async Task Fapi1_Par_Accepts_WhenCodeChallengePresent()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportParameters(includePrivateParameters: false);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(publicKey));
        var jwksJson = JsonSerializer.Serialize(
            new { keys = new[] { new { kty = "RSA", n = jwk.N, e = jwk.E, use = "sig" } } });

        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi1Advanced;
            opts.PushedAuthorizationEnabled = true;
            opts.JarmEnabled = true;
            opts.StaticClients = [
                .. opts.StaticClients,
                new Client
                {
                    ClientId = "fapi1-par-ok",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "private_key_jwt",
                    JwksJson = jwksJson,
                },
            ];
        });

        var signingKey = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: true));
        var assertion = BuildClientJwtAssertion(
            "fapi1-par-ok",
            "https://auth.test.example.com/connect/par",
            signingKey,
            SecurityAlgorithms.RsaSha256);

        var resp = await app.Client.PostAsync("/connect/par",
            new FormUrlEncodedContent(
            [
                new("client_id", "fapi1-par-ok"),
                new("response_type", "code"),
                new("redirect_uri", "https://client.test.example.com/callback"),
                new("scope", "openid"),
                new("nonce", "test-nonce"),
                new("code_challenge", "some_s256_challenge_value"),
                new("code_challenge_method", "S256"),
                new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", assertion),
            ]));

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("request_uri", out _));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FAPI 2.0 — client authentication method enforcement
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Fapi2_TokenEndpoint_Rejects_ClientSecretBasicAuth()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi2Security;
        });

        // Attempt client_credentials with client_secret_basic — must be rejected.
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Fapi1_TokenEndpoint_Rejects_ClientSecretBasicAuth()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FapiProfile = FapiProfile.Fapi1Advanced;
        });

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", "profile"),
            ]),
        });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    /// <summary>Builds a minimal FAPI 2.0-compliant ProviderOptions for validator unit tests.</summary>
    private static ProviderOptions BuildFapi2CompliantOptions() =>
        new()
        {
            FapiProfile = FapiProfile.Fapi2Security,
            FapiProfileValidationEnabled = true,
            DPoPEnabled = true,
            RequirePushedAuthorization = true,
            PushedAuthorizationEnabled = true,
            PushedAuthorizationLifetimeSeconds = 90,
            AuthorizationCodeLifetimeSeconds = 60,
            IssuerIdentificationEnabled = true,
        };

    /// <summary>Builds a signed JWT client assertion for private_key_jwt auth.</summary>
    private static string BuildClientJwtAssertion(
        string clientId, string audience, SecurityKey signingKey, string alg)
    {
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Subject = new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("sub", clientId)]),
            Audience = audience,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString(),
            },
            SigningCredentials = new SigningCredentials(signingKey, alg),
        });
    }
}
