using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Tests;

/// <summary>P5.1 discovery accuracy, P5.2 signed/encrypted UserInfo, P5.6 error rendering.</summary>
public sealed class DiscoveryAndResponseFormatTests
{
    private const string Issuer = "https://auth.test.example.com";

    private static async Task<JsonObject> DiscoveryAsync(TestWebApp app) =>
        JsonNode.Parse(await app.Client.GetStringAsync("/.well-known/openid-configuration"))!.AsObject();

    private static string[] Strings(JsonNode? node) => node?.AsArray().Select(n => n!.GetValue<string>()).ToArray() ?? [];

    // ── P5.1 Discovery ──────────────────────────────────────────────────────

    /// <summary>
    /// The default document, key by key. A change here is a change to what the provider tells
    /// every relying party; update the snapshot deliberately.
    /// </summary>
    [Fact]
    public async Task Discovery_DefaultConfiguration_MatchesSnapshot()
    {
        await using var app = TestWebApp.Create();
        var actual = await DiscoveryAsync(app);

        var expected = JsonNode.Parse(DefaultSnapshot)!.AsObject();
        var mismatches = expected.Select(p => p.Key).Union(actual.Select(p => p.Key))
            .Where(key => !JsonNode.DeepEquals(expected[key], actual[key]))
            .Select(key => $"{key}: expected {expected[key]?.ToJsonString() ?? "(absent)"}, actual {actual[key]?.ToJsonString() ?? "(absent)"}")
            .ToList();
        Assert.True(mismatches.Count == 0, string.Join(Environment.NewLine, mismatches));
    }

    private const string DefaultSnapshot = """
    {
      "issuer": "https://auth.test.example.com",
      "authorization_endpoint": "https://auth.test.example.com/connect/authorize",
      "token_endpoint": "https://auth.test.example.com/connect/token",
      "userinfo_endpoint": "https://auth.test.example.com/connect/userinfo",
      "introspection_endpoint": "https://auth.test.example.com/connect/introspect",
      "revocation_endpoint": "https://auth.test.example.com/connect/revoke",
      "jwks_uri": "https://auth.test.example.com/.well-known/jwks.json",
      "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "code id_token token", "id_token token"],
      "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token"],
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["RS256"],
      "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt", "none"],
      "token_endpoint_auth_signing_alg_values_supported": ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"],
      "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"],
      "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"],
      "code_challenge_methods_supported": ["S256"],
      "scopes_supported": ["openid", "profile"],
      "response_modes_supported": ["query", "fragment", "form_post"],
      "claims_parameter_supported": true,
      "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid",
        "birthdate", "family_name", "gender", "given_name", "locale", "middle_name", "name", "nickname",
        "picture", "preferred_username", "profile", "updated_at", "website", "zoneinfo"],
      "prompt_values_supported": ["none", "login", "consent", "select_account"],
      "request_uri_parameter_supported": false,
      "authorization_response_iss_parameter_supported": true,
      "frontchannel_logout_supported": false,
      "frontchannel_logout_session_supported": false,
      "id_token_encryption_alg_values_supported": ["RSA-OAEP"],
      "id_token_encryption_enc_values_supported": ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"],
      "userinfo_signing_alg_values_supported": ["RS256"],
      "userinfo_encryption_alg_values_supported": ["RSA-OAEP"],
      "userinfo_encryption_enc_values_supported": ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]
    }
    """;

    [Fact]
    public async Task Discovery_Fapi2_AdvertisesOnlyWhatTheProfileAccepts()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.FapiProfile = FapiProfile.Fapi2Security;
            o.PushedAuthorizationEnabled = true;
            o.StaticClients = [];
        });
        var doc = await DiscoveryAsync(app);

        Assert.Equal(["code"], Strings(doc["response_types_supported"]));
        Assert.DoesNotContain("implicit", Strings(doc["grant_types_supported"]));
        Assert.Equal(["private_key_jwt"], Strings(doc["token_endpoint_auth_methods_supported"]));
        Assert.DoesNotContain(Strings(doc["token_endpoint_auth_signing_alg_values_supported"]), a => a.StartsWith("HS"));
    }

    [Fact]
    public async Task Discovery_Fapi1_AdvertisesCodeAndHybrid()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.FapiProfile = FapiProfile.Fapi1Advanced;
            o.StaticClients = [];
        });
        var doc = await DiscoveryAsync(app);

        Assert.Equal(["code", "code id_token"], Strings(doc["response_types_supported"]));
        Assert.Contains("implicit", Strings(doc["grant_types_supported"]));
        Assert.DoesNotContain("none", Strings(doc["token_endpoint_auth_methods_supported"]));
    }

    [Fact]
    public async Task Discovery_RequestObjectEncryption_FollowsJarAndEncryptionKeys()
    {
        await using var withoutJar = TestWebApp.Create();
        var doc = await DiscoveryAsync(withoutJar);
        Assert.Null(doc["request_object_encryption_alg_values_supported"]);
        Assert.Null(doc["request_object_encryption_enc_values_supported"]);

        // Decryption accepts GCM as well; the algorithms are those of the provider's encryption keys.
        await using var withKeys = TestWebApp.Create(o => o.JarEnabled = true,
            b => b.AddEncryptionKey(new RsaSecurityKey(RSA.Create(2048))));
        doc = await DiscoveryAsync(withKeys);
        Assert.Equal(["RSA-OAEP"], Strings(doc["request_object_encryption_alg_values_supported"]));
        Assert.Contains("A256GCM", Strings(doc["request_object_encryption_enc_values_supported"]));
    }

    [Fact]
    public async Task Discovery_OptionalFeatures_AreAdvertisedWhenEnabled()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.VciEnabled = true;
            o.VciPreAuthorizedAnonymousAccess = true;
            o.ClientIdMetadataDocumentEnabled = true;
            o.JarEnabled = true;
            o.JarRequireSignedRequestObject = true;
            o.ClientAttestationTrustedAttesters["https://attester.example.com"] =
                """{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}""";
        });
        var doc = await DiscoveryAsync(app);

        Assert.Contains("urn:ietf:params:oauth:grant-type:pre-authorized_code", Strings(doc["grant_types_supported"]));
        Assert.True(doc["pre-authorized_grant_anonymous_access_supported"]!.GetValue<bool>());
        Assert.Contains("openid_credential", Strings(doc["authorization_details_types_supported"]));
        Assert.True(doc["client_id_metadata_document_supported"]!.GetValue<bool>());
        Assert.True(doc["require_signed_request_object"]!.GetValue<bool>());
        Assert.Contains("attest_jwt_client_auth", Strings(doc["token_endpoint_auth_methods_supported"]));
    }

    // ── P5.2 UserInfo signing and encryption ────────────────────────────────

    private static readonly RSA ClientEncryptionKey = RSA.Create(2048);

    private static string ClientEncryptionJwks()
    {
        var p = ClientEncryptionKey.ExportParameters(false);
        return JsonSerializer.Serialize(new { keys = new[] { new
        {
            kty = "RSA", use = "enc", kid = "client-enc",
            n = Base64UrlEncoder.Encode(p.Modulus!), e = Base64UrlEncoder.Encode(p.Exponent!),
        } } });
    }

    private static TestWebApp CreateUserInfoApp(Client client) =>
        TestWebApp.Create(o => o.StaticClients = [.. o.StaticClients, client]);

    private static async Task<HttpResponseMessage> UserInfoAsync(TestWebApp app, string clientId)
    {
        var token = await app.IssueUserAccessTokenAsync("alice", clientId, "openid", "profile");
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await app.Client.SendAsync(request);
    }

    private static async Task<TokenValidationResult> ValidateSignedAsync(TestWebApp app, string jwt, string clientId,
        SecurityKey? decryptionKey = null)
    {
        var jwks = new JsonWebKeySet(await app.Client.GetStringAsync("/.well-known/jwks.json"));
        return await new JsonWebTokenHandler().ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidIssuer = Issuer,
            ValidAudience = clientId,
            ValidateLifetime = false,
            TokenDecryptionKey = decryptionKey,
        });
    }

    [Fact]
    public async Task UserInfo_Signed_IsJwtFromTheProvider()
    {
        await using var app = CreateUserInfoApp(new Client
        {
            ClientId = "ui-signed", ClientSecret = "s", AllowedScopes = ["openid", "profile"],
            UserInfoSignedResponseAlg = "RS256",
        });

        var resp = await UserInfoAsync(app, "ui-signed");

        Assert.Equal("application/jwt", resp.Content.Headers.ContentType?.MediaType);
        var result = await ValidateSignedAsync(app, await resp.Content.ReadAsStringAsync(), "ui-signed");
        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal("alice", result.Claims["sub"]);
        Assert.Equal("Test alice", result.Claims["name"]);
    }

    [Fact]
    public async Task UserInfo_Encrypted_IsSignedThenEncrypted()
    {
        await using var app = CreateUserInfoApp(new Client
        {
            ClientId = "ui-encrypted", ClientSecret = "s", AllowedScopes = ["openid", "profile"],
            JwksJson = ClientEncryptionJwks(),
            UserInfoEncryptedResponseAlg = "RSA-OAEP",
        });

        var resp = await UserInfoAsync(app, "ui-encrypted");
        var jwe = await resp.Content.ReadAsStringAsync();

        Assert.Equal("application/jwt", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal(5, jwe.Split('.').Length);
        var header = new JsonWebToken(jwe);
        Assert.Equal(("RSA-OAEP", "A128CBC-HS256"), (header.Alg, header.Enc));

        var result = await ValidateSignedAsync(app, jwe, "ui-encrypted", new RsaSecurityKey(ClientEncryptionKey) { KeyId = "client-enc" });
        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal("alice", result.Claims["sub"]);
    }

    [Fact]
    public async Task UserInfo_Default_IsPlainJson()
    {
        await using var app = TestWebApp.Create();

        var resp = await UserInfoAsync(app, "test-client");

        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public void Options_EncryptedResponseWithoutClientKeys_FailsValidation()
    {
        var options = new ProviderOptions
        {
            Issuer = Issuer,
            StaticClients =
            [
                new Client { ClientId = "a", ClientSecret = "s", UserInfoEncryptedResponseAlg = "RSA-OAEP" },
                new Client { ClientId = "b", ClientSecret = "s", JwksJson = ClientEncryptionJwks(),
                    IdTokenEncryptedResponseAlg = "RSA-OAEP", IdTokenEncryptedResponseEnc = "A256GCM" },
            ],
        };

        var failures = new ProviderOptionsValidator().Validate(null, options).Failures ?? [];

        Assert.Contains(failures, f => f.Contains("'a'") && f.Contains("require JwksJson"));
        Assert.Contains(failures, f => f.Contains("'b'") && f.Contains("A256GCM"));
    }

    [Fact]
    public async Task IdToken_Encryption_DefaultsToA128CbcHs256()
    {
        await using var app = TestWebApp.Create(o =>
        {
            var client = o.StaticClients.First(c => c.ClientId == "test-client");
            o.StaticClients =
            [
                .. o.StaticClients.Where(c => c != client),
                new Client
                {
                    ClientId = client.ClientId, ClientSecret = client.ClientSecret,
                    AllowedGrantTypes = client.AllowedGrantTypes, AllowedScopes = client.AllowedScopes,
                    RedirectUris = client.RedirectUris, RequirePkce = false, RequireConsent = false,
                    JwksJson = ClientEncryptionJwks(), IdTokenEncryptedResponseAlg = "RSA-OAEP",
                },
            ];
        });

        var token = await Oidc.CodeFlowAsync(app);
        var idToken = new JsonWebToken(token.GetProperty("id_token").GetString()!);

        Assert.Equal(("RSA-OAEP", "A128CBC-HS256"), (idToken.Alg, idToken.Enc));
    }

    // ── P5.6 Error rendering ────────────────────────────────────────────────

    private static TestWebApp CreateRenderingApp() => TestWebApp.Create(o =>
    {
        o.LogoutEnabled = true;
        o.RenderErrorPage = (_, error) => Task.FromResult(
            Results.Content($"<h1>Sorry: {error.Error}</h1>", "text/html", statusCode: 400));
    });

    [Fact]
    public async Task RenderErrorPage_UsedForUnredirectableAuthorizationErrors()
    {
        await using var app = CreateRenderingApp();

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "no-such-client"), ("response_type", "code"), ("redirect_uri", Oidc.Callback));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
        Assert.Contains("Sorry: invalid_request", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RenderErrorPage_NotUsedForRedirectableErrors()
    {
        await using var app = CreateRenderingApp();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", Oidc.Callback), ("prompt", "bogus"));

        Oidc.AssertRedirectError(resp, "invalid_request");
    }

    [Fact]
    public async Task RenderErrorPage_UsedForInvalidLogoutRequests()
    {
        await using var app = CreateRenderingApp();

        var resp = await app.Client.GetAsync(
            "/connect/end_session?client_id=test-client&post_logout_redirect_uri=https%3A%2F%2Fevil.example.com%2F");

        Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
        Assert.Contains("Sorry: invalid_request", await resp.Content.ReadAsStringAsync());
    }
}
