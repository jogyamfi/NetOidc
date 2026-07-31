using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Vci;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Integration tests for Phase 8: OpenID Federation 1.1, OID4VCI 1.0,
/// Client ID Metadata Document, and CORS handling.
/// </summary>
public sealed class Phase8Tests
{
    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // OpenID Federation 1.1
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Federation_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // FederationEnabled = false by default

        var resp = await app.Client.GetAsync("/.well-known/openid-federation");

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Federation_Returns_EntityStatementJwt_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.FederationEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-federation");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("entity-statement+jwt",
            resp.Content.Headers.ContentType?.MediaType ?? "");

        // The body must be a valid three-part JWT
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(3, body.Split('.').Length);
    }

    [Fact]
    public async Task Federation_EntityConfiguration_HasCorrectIssClaims()
    {
        await using var app = TestWebApp.Create(opts => opts.FederationEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-federation");
        var jwt = await resp.Content.ReadAsStringAsync();

        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(jwt);

        Assert.Equal("entity-statement+jwt", token.Typ);
        // iss and sub must equal the issuer
        Assert.Equal("https://auth.test.example.com", token.Issuer);
        Assert.Equal("https://auth.test.example.com", token.GetClaim("sub").Value);
    }

    [Fact]
    public async Task Federation_EntityConfiguration_ContainsMetadataAndJwks()
    {
        await using var app = TestWebApp.Create(opts => opts.FederationEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-federation");
        var jwt = await resp.Content.ReadAsStringAsync();

        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(jwt);

        Assert.True(token.TryGetClaim("metadata", out _), "metadata claim must be present");
        Assert.True(token.TryGetClaim("jwks", out _), "jwks claim must be present");
    }

    [Fact]
    public async Task Federation_EntityConfiguration_HasAuthorityHints_WhenConfigured()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.FederationEnabled = true;
            opts.FederationAuthorityHints.Add("https://ta.example.com");
        });

        var resp = await app.Client.GetAsync("/.well-known/openid-federation");
        var jwt = await resp.Content.ReadAsStringAsync();

        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(jwt);

        Assert.True(token.TryGetClaim("authority_hints", out var hints));
        Assert.Contains("https://ta.example.com", hints.Value);
    }

    [Fact]
    public async Task Discovery_Advertises_ClientRegistrationTypes_WhenFederationEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.FederationEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        Assert.True(doc.RootElement.TryGetProperty("client_registration_types_supported", out _));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // OID4VCI 1.0 — Nonce endpoint
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Vci_Nonce_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // VciEnabled = false

        var resp = await app.Client.PostAsync("/connect/nonce", null);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Vci_Nonce_ReturnsNonce_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.VciEnabled = true);

        var resp = await app.Client.PostAsync("/connect/nonce", null);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("c_nonce", out var nonce) &&
                    !string.IsNullOrEmpty(nonce.GetString()));
        Assert.True(body.RootElement.TryGetProperty("c_nonce_expires_in", out var exp) &&
                    exp.GetInt32() > 0);
    }

    [Fact]
    public async Task Vci_Nonce_TwoCalls_ReturnDifferentNonces()
    {
        await using var app = TestWebApp.Create(opts => opts.VciEnabled = true);

        var n1 = JsonDocument.Parse(await (await app.Client.PostAsync("/connect/nonce", null))
            .Content.ReadAsStringAsync()).RootElement.GetProperty("c_nonce").GetString();
        var n2 = JsonDocument.Parse(await (await app.Client.PostAsync("/connect/nonce", null))
            .Content.ReadAsStringAsync()).RootElement.GetProperty("c_nonce").GetString();

        Assert.NotEqual(n1, n2);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // OID4VCI 1.0 — Credential issuer metadata
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Vci_IssuerMetadata_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // VciEnabled = false

        var resp = await app.Client.GetAsync("/.well-known/openid-credential-issuer");

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Vci_IssuerMetadata_ReturnsCorrectShape_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.VciEnabled = true;
            opts.VciCredentialConfigurations.Add(new CredentialConfiguration
            {
                Id = "TestDegree",
                Format = "jwt_vc_json",
                Scope = "TestDegree",
            });
        });

        var resp = await app.Client.GetAsync("/.well-known/openid-credential-issuer");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        Assert.True(body.RootElement.TryGetProperty("credential_issuer", out _));
        Assert.True(body.RootElement.TryGetProperty("credential_endpoint", out _));
        Assert.True(body.RootElement.TryGetProperty("nonce_endpoint", out _));
        Assert.True(body.RootElement.TryGetProperty("credential_configurations_supported", out var configs));
        Assert.True(configs.TryGetProperty("TestDegree", out _));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // OID4VCI 1.0 — Credential endpoint
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Vci_Credential_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // VciEnabled = false

        var resp = await app.Client.PostAsync("/connect/credential",
            new StringContent("{}", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Vci_Credential_Returns401_WithoutBearerToken()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.VciEnabled = true;
            opts.IssueCredential = (_, _, _) => Task.FromResult("test-credential");
        });

        var resp = await app.Client.PostAsync("/connect/credential",
            new StringContent("{}", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Vci_Credential_Returns400_WithoutConfigurationId()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.VciEnabled = true;
            opts.IssueCredential = (_, _, _) => Task.FromResult("test-credential");
        });

        // Obtain an access token via client_credentials first
        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials"), new("scope", "profile")]),
        });
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        var accessToken = tokenBody.RootElement.GetProperty("access_token").GetString()!;

        var credResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/credential")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse($"Bearer {accessToken}") },
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        });

        Assert.Equal(HttpStatusCode.BadRequest, credResp.StatusCode);
        var err = JsonDocument.Parse(await credResp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", err.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Vci_Credential_Returns400_ForUnknownConfigurationId()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.VciEnabled = true;
            opts.IssueCredential = (_, _, _) => Task.FromResult("test-credential");
        });

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials"), new("scope", "profile")]),
        });
        var accessToken = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        var credResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/credential")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse($"Bearer {accessToken}") },
            Content = new StringContent(
                "{\"credential_configuration_id\":\"unknown\"}", Encoding.UTF8, "application/json"),
        });

        Assert.Equal(HttpStatusCode.BadRequest, credResp.StatusCode);
    }

    [Fact]
    public async Task Vci_Credential_IssuesCredential_WhenValid()
    {
        const string ExpectedCredential = "eyJhbGciOiJSUzI1NiJ9.test.credential";

        await using var app = TestWebApp.Create(opts =>
        {
            opts.VciEnabled = true;
            opts.VciCredentialConfigurations.Add(new CredentialConfiguration
            {
                Id = "TestDegree",
                Format = "jwt_vc_json",
            });
            opts.IssueCredential = (sub, configId, _) =>
                Task.FromResult(ExpectedCredential);
        });

        // Get access token via client_credentials
        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials"), new("scope", "profile")]),
        });
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        var accessToken = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        // Request credential
        var credResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/credential")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse($"Bearer {accessToken}") },
            Content = new StringContent(
                "{\"credential_configuration_id\":\"TestDegree\"}", Encoding.UTF8, "application/json"),
        });

        Assert.Equal(HttpStatusCode.OK, credResp.StatusCode);
        var body = JsonDocument.Parse(await credResp.Content.ReadAsStringAsync());
        Assert.Equal(ExpectedCredential, body.RootElement.GetProperty("credential").GetString());
    }

    [Fact]
    public async Task Vci_Credential_InvalidProofTyp_Returns400()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.VciEnabled = true;
            opts.VciCredentialConfigurations.Add(new CredentialConfiguration
            {
                Id = "TestDegree",
                Format = "jwt_vc_json",
            });
            opts.IssueCredential = (_, _, _) => Task.FromResult("test-credential");
        });

        var tokenResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials"), new("scope", "profile")]),
        });
        var accessToken = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("access_token").GetString()!;

        // Proof with missing jwt field for proof_type=jwt
        var payload = """{"credential_configuration_id":"TestDegree","proof":{"proof_type":"jwt","jwt":""}}""";
        var credResp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/credential")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse($"Bearer {accessToken}") },
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        });

        Assert.Equal(HttpStatusCode.BadRequest, credResp.StatusCode);
        var err = JsonDocument.Parse(await credResp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_proof", err.RootElement.GetProperty("error").GetString());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Client ID Metadata Document (draft)
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task ClientIdMetadata_Returns404_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // ClientIdMetadataDocumentEnabled = false

        var resp = await app.Client.GetAsync("/.well-known/client_id_metadata/test-client");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task ClientIdMetadata_Returns404_ForUnknownClient()
    {
        await using var app = TestWebApp.Create(opts =>
            opts.ClientIdMetadataDocumentEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/client_id_metadata/no-such-client");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task ClientIdMetadata_ReturnsPublicFields_ForKnownClient()
    {
        await using var app = TestWebApp.Create(opts =>
            opts.ClientIdMetadataDocumentEnabled = true);

        var resp = await app.Client.GetAsync("/.well-known/client_id_metadata/test-client");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("test-client", body.RootElement.GetProperty("client_id").GetString());
        Assert.True(body.RootElement.TryGetProperty("grant_types", out _));
        // client_secret must NOT be exposed
        Assert.False(body.RootElement.TryGetProperty("client_secret", out _));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CORS handling
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Cors_Discovery_DoesNotReturnCorsHeaders_WhenDisabled()
    {
        await using var app = TestWebApp.Create(); // CorsEnabled = false

        var req = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        req.Headers.Add("Origin", "https://rp.example.com");
        var resp = await app.Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.False(resp.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Cors_Discovery_ReturnsWildcard_WhenEnabledWithNoOrigins()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.CorsEnabled = true;
            // CorsAllowedOrigins is empty → allow all
        });

        var policy = app.Services
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<
                Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>>()
            .Value.GetPolicy("NetOidcCors");

        Assert.NotNull(policy);
        Assert.True(policy.AllowAnyOrigin);
    }

    [Fact]
    public async Task Cors_Policy_RestrictsOrigins_WhenOriginsConfigured()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.CorsEnabled = true;
            opts.CorsAllowedOrigins.Add("https://allowed.example.com");
        });

        var policy = app.Services
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<
                Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>>()
            .Value.GetPolicy("NetOidcCors");

        Assert.NotNull(policy);
        Assert.False(policy.AllowAnyOrigin);
        Assert.Contains("https://allowed.example.com", policy.Origins);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // VciService unit tests
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public void VciService_IssueNonce_ReturnsNonEmptyString()
    {
        var opts = Microsoft.Extensions.Options.Options.Create(new Configuration.ProviderOptions
        {
            VciNonceLifetimeSeconds = 300
        });
        var svc = new NetOidc.Provider.Vci.VciService(opts);

        var nonce = svc.IssueNonce();

        Assert.NotEmpty(nonce);
    }

    [Fact]
    public void VciService_ConsumeNonce_ReturnsTrueOnFirstConsume()
    {
        var opts = Microsoft.Extensions.Options.Options.Create(new Configuration.ProviderOptions
        {
            VciNonceLifetimeSeconds = 300
        });
        var svc = new NetOidc.Provider.Vci.VciService(opts);
        var nonce = svc.IssueNonce();

        Assert.True(svc.ConsumeNonce(nonce));
    }

    [Fact]
    public void VciService_ConsumeNonce_ReturnsFalseOnSecondConsume()
    {
        var opts = Microsoft.Extensions.Options.Options.Create(new Configuration.ProviderOptions
        {
            VciNonceLifetimeSeconds = 300
        });
        var svc = new NetOidc.Provider.Vci.VciService(opts);
        var nonce = svc.IssueNonce();
        svc.ConsumeNonce(nonce);

        Assert.False(svc.ConsumeNonce(nonce));
    }

    [Fact]
    public void VciService_ConsumeNonce_ReturnsFalseForUnknownNonce()
    {
        var opts = Microsoft.Extensions.Options.Options.Create(new Configuration.ProviderOptions
        {
            VciNonceLifetimeSeconds = 300
        });
        var svc = new NetOidc.Provider.Vci.VciService(opts);

        Assert.False(svc.ConsumeNonce("never-issued-nonce"));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FederationService unit tests
    // ════════════════════════════════════════════════════════════════════════════

    [Fact]
    public void FederationService_BuildEntityConfiguration_ProducesValidJwt()
    {
        var opts = Microsoft.Extensions.Options.Options.Create(new Configuration.ProviderOptions
        {
            Issuer = "https://idp.example.com",
            FederationEnabled = true,
            FederationEntityStatementLifetimeSeconds = 3600,
        });
        var keyProvider = new Jose.SigningKeyProvider();
        var svc = new NetOidc.Provider.Federation.FederationService(opts, keyProvider);

        var jwt = svc.BuildEntityConfiguration();

        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(jwt);

        Assert.Equal("entity-statement+jwt", token.Typ);
        Assert.Equal("https://idp.example.com", token.Issuer);
        Assert.Equal("https://idp.example.com", token.GetClaim("sub").Value);
        Assert.True(token.TryGetClaim("metadata", out _));
        Assert.True(token.TryGetClaim("jwks", out _));
    }
}
