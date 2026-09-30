using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Tests;

/// <summary>P5.6: DCR keys, algorithms and RP Metadata Choices; attestation-based client authentication.</summary>
public sealed class DcrMetadataAndAttestationTests
{
    private const string Issuer = "https://auth.test.example.com";
    private const string Redirect = "https://rp.example.org/cb";

    private static JsonObject PublicJwks(AsymmetricSecurityKey key, string kid)
    {
        var jwk = key switch
        {
            RsaSecurityKey rsa => JsonWebKeyConverter.ConvertFromRSASecurityKey(rsa),
            ECDsaSecurityKey ec => JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ec),
            _ => throw new NotSupportedException(),
        };
        var node = JsonNode.Parse(JsonSerializer.Serialize(new Dictionary<string, string?>
        {
            ["kty"] = jwk.Kty, ["kid"] = kid, ["n"] = jwk.N, ["e"] = jwk.E, ["crv"] = jwk.Crv, ["x"] = jwk.X, ["y"] = jwk.Y,
        }.Where(p => p.Value is not null).ToDictionary()))!;
        return new JsonObject { ["keys"] = new JsonArray(node) };
    }

    // ── DCR ─────────────────────────────────────────────────────────────────

    private static TestWebApp CreateDcrApp(FakeWeb? web = null)
    {
        void Configure(ProviderOptions o)
        {
            o.DcrEnabled = true;
            o.DcrAllowedGrantTypes = ["authorization_code", "refresh_token", "client_credentials"];
        }
        return web is null ? TestWebApp.Create(Configure) : web.CreateApp(Configure);
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> RegisterAsync(TestWebApp app, JsonObject metadata)
    {
        metadata["redirect_uris"] ??= new JsonArray(Redirect);
        var resp = await app.Client.PostAsJsonAsync("/connect/register", metadata);
        return (resp.StatusCode, JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.Clone());
    }

    private static string Assertion(SecurityKey key, string alg, string clientId) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = Issuer + "/connect/token",
            Expires = DateTime.UtcNow.AddMinutes(1),
            Claims = new Dictionary<string, object> { ["sub"] = clientId, ["jti"] = Guid.NewGuid().ToString() },
            SigningCredentials = new SigningCredentials(key, alg),
        });

    [Fact]
    public async Task PrivateKeyJwt_WithInlineJwks_RegistersAndAuthenticates()
    {
        await using var app = CreateDcrApp();
        var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k1" };

        var (status, body) = await RegisterAsync(app, new JsonObject
        {
            ["token_endpoint_auth_method"] = "private_key_jwt",
            ["grant_types"] = new JsonArray("client_credentials"),
            ["jwks"] = PublicJwks(key, "k1"),
        });

        Assert.Equal(HttpStatusCode.Created, status);
        Assert.False(body.TryGetProperty("client_secret", out _));
        Assert.Equal("k1", body.GetProperty("jwks").GetProperty("keys")[0].GetProperty("kid").GetString());
        var clientId = body.GetProperty("client_id").GetString()!;

        var token = await Oidc.TokenAsync(app,
        [
            new("grant_type", "client_credentials"),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", Assertion(key, SecurityAlgorithms.RsaSha256, clientId)),
        ]);
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
    }

    [Fact]
    public async Task JwksUri_IsFetched()
    {
        var web = new FakeWeb();
        var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "remote" };
        web.Serve("https://rp.example.org/jwks.json", PublicJwks(key, "remote").ToJsonString());
        await using var app = CreateDcrApp(web);

        var (status, body) = await RegisterAsync(app, new JsonObject
        {
            ["token_endpoint_auth_method"] = "private_key_jwt",
            ["jwks_uri"] = "https://rp.example.org/jwks.json",
        });

        Assert.Equal(HttpStatusCode.Created, status);
        Assert.Equal("remote", body.GetProperty("jwks").GetProperty("keys")[0].GetProperty("kid").GetString());
    }

    [Fact]
    public async Task InvalidKeyMetadata_IsRejected()
    {
        var web = new FakeWeb();
        await using var app = CreateDcrApp(web);
        var rsa = RSA.Create(2048);
        var withPrivate = JsonNode.Parse(JsonSerializer.Serialize(new { keys = new[] { new
        {
            kty = "RSA",
            n = Base64UrlEncoder.Encode(rsa.ExportParameters(true).Modulus!),
            e = Base64UrlEncoder.Encode(rsa.ExportParameters(true).Exponent!),
            d = Base64UrlEncoder.Encode(rsa.ExportParameters(true).D!),
        } } }))!.AsObject();
        var publicJwks = PublicJwks(new RsaSecurityKey(rsa), "k");

        foreach (var metadata in new[]
        {
            new JsonObject { ["token_endpoint_auth_method"] = "private_key_jwt" },
            new JsonObject { ["token_endpoint_auth_method"] = "private_key_jwt", ["jwks"] = withPrivate },
            new JsonObject { ["jwks"] = publicJwks.DeepClone(), ["jwks_uri"] = "https://rp.example.org/jwks.json" },
            new JsonObject { ["token_endpoint_auth_method"] = "private_key_jwt", ["jwks_uri"] = "https://rp.example.org/missing.json" },
            new JsonObject { ["token_endpoint_auth_method"] = "tls_client_auth" },
        })
        {
            var (status, body) = await RegisterAsync(app, metadata);
            Assert.True(status == HttpStatusCode.BadRequest, metadata.ToJsonString());
            Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task RpMetadataChoices_ProviderPicksFirstSupportedValue()
    {
        await using var app = CreateDcrApp();
        var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k" };

        var (status, body) = await RegisterAsync(app, new JsonObject
        {
            ["token_endpoint_auth_methods_supported"] = new JsonArray("tls_client_auth", "private_key_jwt", "client_secret_basic"),
            ["id_token_signing_alg_values_supported"] = new JsonArray("EdDSA", "ES256", "RS256"),
            ["request_object_signing_alg_values_supported"] = new JsonArray("PS256", "RS256"),
            ["id_token_encryption_alg_values_supported"] = new JsonArray("ECDH-ES", "RSA-OAEP-256", "RSA-OAEP"),
            ["jwks"] = PublicJwks(key, "k"),
        });

        Assert.Equal(HttpStatusCode.Created, status);
        Assert.Equal("private_key_jwt", body.GetProperty("token_endpoint_auth_method").GetString());
        Assert.Equal("RS256", body.GetProperty("id_token_signed_response_alg").GetString());
        Assert.Equal("PS256", body.GetProperty("request_object_signing_alg").GetString());
        Assert.Equal("RSA-OAEP", body.GetProperty("id_token_encrypted_response_alg").GetString());
        Assert.Equal("A128CBC-HS256", body.GetProperty("id_token_encrypted_response_enc").GetString());
    }

    [Fact]
    public async Task RpMetadataChoices_NothingSupported_IsRejected()
    {
        await using var app = CreateDcrApp();

        var (status, body) = await RegisterAsync(app, new JsonObject
        {
            ["id_token_signing_alg_values_supported"] = new JsonArray("EdDSA", "ES512"),
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
    }

    [Theory]
    [InlineData("id_token_signed_response_alg", "ES256")]      // no EC signing key configured
    [InlineData("userinfo_signed_response_alg", "none")]
    [InlineData("id_token_encrypted_response_alg", "RSA-OAEP")] // encryption needs client keys
    [InlineData("userinfo_encrypted_response_enc", "A128CBC-HS256")] // enc without alg
    [InlineData("id_token_encrypted_response_enc", "A256GCM")]
    public async Task UnsupportedAlgorithms_AreRejected(string name, string value)
    {
        await using var app = CreateDcrApp();

        var (status, body) = await RegisterAsync(app, new JsonObject { [name] = value });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Update_KeepsIdentity_AndRegistrationToken()
    {
        await using var app = CreateDcrApp();
        var (_, created) = await RegisterAsync(app, new JsonObject { ["client_name"] = "Before" });
        var clientId = created.GetProperty("client_id").GetString()!;
        var registrationToken = created.GetProperty("registration_access_token").GetString()!;

        var request = new HttpRequestMessage(HttpMethod.Put, $"/connect/register/{clientId}")
        {
            Content = JsonContent.Create(new JsonObject
            {
                ["client_id"] = clientId,
                ["redirect_uris"] = new JsonArray(Redirect),
                ["client_name"] = "After",
                ["userinfo_signed_response_alg"] = "RS256",
            }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", registrationToken);
        var resp = await app.Client.SendAsync(request);
        var updated = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(clientId, updated.GetProperty("client_id").GetString());
        Assert.Equal(created.GetProperty("client_id_issued_at").GetInt64(), updated.GetProperty("client_id_issued_at").GetInt64());
        Assert.False(updated.TryGetProperty("registration_access_token", out _));
        Assert.Equal("RS256", updated.GetProperty("userinfo_signed_response_alg").GetString());

        // The original registration access token still manages the client.
        var read = new HttpRequestMessage(HttpMethod.Get, $"/connect/register/{clientId}");
        read.Headers.Authorization = new AuthenticationHeaderValue("Bearer", registrationToken);
        Assert.Equal(HttpStatusCode.OK, (await app.Client.SendAsync(read)).StatusCode);
    }

    // ── Attestation-based client authentication ─────────────────────────────

    private const string Attester = "https://attester.example.com";
    private const string WalletId = "attested-wallet";

    private sealed class Attestation
    {
        public RsaSecurityKey AttesterKey { get; } = new(RSA.Create(2048)) { KeyId = "attester" };
        public ECDsaSecurityKey InstanceKey { get; } = new(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = "instance" };

        public string AttestationJwt(string subject = WalletId, SecurityKey? signer = null, string type = "oauth-client-attestation+jwt")
        {
            var cnf = PublicJwks(InstanceKey, "instance")["keys"]![0]!.DeepClone();
            return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = Attester,
                Expires = DateTime.UtcNow.AddHours(1),
                TokenType = type,
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = subject,
                    ["cnf"] = JsonSerializer.SerializeToElement(new JsonObject { ["jwk"] = cnf }),
                },
                SigningCredentials = new SigningCredentials(signer ?? AttesterKey,
                    signer is ECDsaSecurityKey ? SecurityAlgorithms.EcdsaSha256 : SecurityAlgorithms.RsaSha256),
            });
        }

        public string Pop(string issuer = WalletId, SecurityKey? signer = null, string audience = Issuer, string? jti = null) =>
            new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                IssuedAt = DateTime.UtcNow,
                TokenType = "oauth-client-attestation-pop+jwt",
                Claims = new Dictionary<string, object> { ["jti"] = jti ?? Guid.NewGuid().ToString() },
                SigningCredentials = new SigningCredentials(signer ?? InstanceKey, SecurityAlgorithms.EcdsaSha256),
            });

        public TestWebApp CreateApp(string method = "attest_jwt_client_auth") => TestWebApp.Create(o =>
        {
            o.ClientAttestationTrustedAttesters[Attester] = PublicJwks(AttesterKey, "attester").ToJsonString();
            o.StaticClients = [.. o.StaticClients, new Client
            {
                ClientId = WalletId,
                ClientSecret = method == "client_secret_basic" ? "secret" : null,
                TokenEndpointAuthMethod = method,
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
                RequireConsent = false,
            }];
        });
    }

    private static Task<HttpResponseMessage> AttestedTokenAsync(TestWebApp app, string? attestation, string? pop,
        string? clientId = null, AuthenticationHeaderValue? basic = null)
    {
        var form = new List<KeyValuePair<string, string>> { new("grant_type", "client_credentials"), new("scope", "profile") };
        if (clientId is not null) form.Add(new("client_id", clientId));
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token") { Content = new FormUrlEncodedContent(form) };
        if (attestation is not null) request.Headers.Add("OAuth-Client-Attestation", attestation);
        if (pop is not null) request.Headers.Add("OAuth-Client-Attestation-PoP", pop);
        request.Headers.Authorization = basic;
        return app.Client.SendAsync(request);
    }

    [Fact]
    public async Task Attestation_ValidPair_Authenticates()
    {
        var attestation = new Attestation();
        await using var app = attestation.CreateApp();

        var resp = await AttestedTokenAsync(app, attestation.AttestationJwt(), attestation.Pop(), clientId: WalletId);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Attestation_ReplayedPop_IsRejected()
    {
        var attestation = new Attestation();
        await using var app = attestation.CreateApp();
        var pop = attestation.Pop();

        Assert.Equal(HttpStatusCode.OK, (await AttestedTokenAsync(app, attestation.AttestationJwt(), pop)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await AttestedTokenAsync(app, attestation.AttestationJwt(), pop)).StatusCode);
    }

    [Fact]
    public async Task Attestation_Failures_AreRejected()
    {
        var attestation = new Attestation();
        await using var app = attestation.CreateApp();
        var untrusted = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "attester" };
        var otherInstance = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256));

        var cases = new (string Name, string? Attestation, string? Pop, string? ClientId)[]
        {
            ("untrusted attester", attestation.AttestationJwt(signer: untrusted), attestation.Pop(), null),
            ("wrong attestation typ", attestation.AttestationJwt(type: "JWT"), attestation.Pop(), null),
            ("pop not signed by the instance key", attestation.AttestationJwt(), attestation.Pop(signer: otherInstance), null),
            ("pop issuer is not the client", attestation.AttestationJwt(), attestation.Pop(issuer: "someone-else"), null),
            ("pop for another audience", attestation.AttestationJwt(), attestation.Pop(audience: "https://other.example.com"), null),
            ("client_id differs from the attested client", attestation.AttestationJwt(), attestation.Pop(), "test-client"),
            ("attestation for an unregistered client", attestation.AttestationJwt(subject: "ghost"), attestation.Pop(issuer: "ghost"), null),
            ("pop missing", attestation.AttestationJwt(), null, null),
            ("attestation missing", null, attestation.Pop(), null),
        };
        foreach (var (name, att, pop, clientId) in cases)
            Assert.True((await AttestedTokenAsync(app, att, pop, clientId)).StatusCode == HttpStatusCode.Unauthorized, name);
    }

    [Fact]
    public async Task Attestation_CombinedWithAnotherMethod_IsRejected()
    {
        var attestation = new Attestation();
        await using var app = attestation.CreateApp();

        var resp = await AttestedTokenAsync(app, attestation.AttestationJwt(), attestation.Pop(),
            basic: Oidc.Basic("test-client", "test-secret"));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Attestation_ForClientRegisteredWithOtherMethod_IsRejected()
    {
        var attestation = new Attestation();
        await using var app = attestation.CreateApp(method: "client_secret_basic");

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await AttestedTokenAsync(app, attestation.AttestationJwt(), attestation.Pop())).StatusCode);
    }

    [Fact]
    public void Options_AttestationClientWithoutAttesters_FailsValidation()
    {
        var options = new ProviderOptions
        {
            Issuer = Issuer,
            StaticClients = [new Client { ClientId = "w", TokenEndpointAuthMethod = "attest_jwt_client_auth" }],
        };

        var result = new ProviderOptionsValidator().Validate(null, options);

        Assert.Contains(result.Failures ?? [], f => f.Contains("ClientAttestationTrustedAttesters"));
    }
}
