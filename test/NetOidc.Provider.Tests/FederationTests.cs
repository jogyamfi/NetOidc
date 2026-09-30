using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Federation;

namespace NetOidc.Provider.Tests;

/// <summary>OpenID Federation 1.1 (P5.3): entity configuration, trust chains, registration.</summary>
public sealed class FederationTests
{
    private const string Issuer = "https://auth.test.example.com";
    private const string Anchor = "https://ta.example.org";
    private const string Intermediate = "https://ia.example.org";
    private const string Rp = "https://rp.example.net";

    /// <summary>A federation entity: its federation key and how to sign statements with it.</summary>
    private sealed class Entity
    {
        public Entity(string id)
        {
            Id = id;
            Key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = id.GetHashCode().ToString("x") };
        }

        public string Id { get; }
        public RsaSecurityKey Key { get; }

        public JsonObject Jwks()
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(Key);
            return new JsonObject
            {
                ["keys"] = new JsonArray(new JsonObject
                {
                    ["kty"] = "RSA", ["kid"] = jwk.Kid, ["n"] = jwk.N, ["e"] = jwk.E, ["alg"] = "RS256", ["use"] = "sig",
                }),
            };
        }

        public string Sign(JsonObject payload, string type = "entity-statement+jwt", TimeSpan? lifetime = null)
        {
            var now = DateTime.UtcNow;
            return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                IssuedAt = now,
                NotBefore = now,
                Expires = now + (lifetime ?? TimeSpan.FromHours(1)),
                TokenType = type,
                SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.RsaSha256),
                Claims = payload.ToDictionary(p => p.Key, p => (object)JsonSerializer.SerializeToElement(p.Value)),
            });
        }
    }

    /// <summary>A trust anchor, an optional intermediate and an RP, served through <see cref="FakeWeb"/>.</summary>
    private sealed class Federation
    {
        public FakeWeb Web { get; } = new();
        public Entity TrustAnchor { get; } = new(Anchor);
        public Entity Mid { get; } = new(Intermediate);
        public Entity RelyingParty { get; } = new(Rp);

        /// <summary>The RP's protocol key (private_key_jwt, request objects), published in its metadata.</summary>
        public RsaSecurityKey RpProtocolKey { get; } = new(RSA.Create(2048)) { KeyId = "rp-protocol" };

        public JsonObject RpMetadata { get; }

        public Federation()
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(RpProtocolKey);
            RpMetadata = new JsonObject
            {
                ["redirect_uris"] = new JsonArray("https://rp.example.net/cb"),
                ["grant_types"] = new JsonArray("authorization_code"),
                ["response_types"] = new JsonArray("code"),
                ["scope"] = "openid profile",
                ["client_name"] = "Federated RP",
                ["token_endpoint_auth_method"] = "private_key_jwt",
                ["jwks"] = new JsonObject
                {
                    ["keys"] = new JsonArray(new JsonObject
                    {
                        ["kty"] = "RSA", ["kid"] = jwk.Kid, ["n"] = jwk.N, ["e"] = jwk.E, ["alg"] = "RS256", ["use"] = "sig",
                    }),
                },
            };
        }

        public JsonObject RpConfiguration(params string[] authorityHints) => new()
        {
            ["iss"] = Rp,
            ["sub"] = Rp,
            ["jwks"] = RelyingParty.Jwks(),
            ["authority_hints"] = new JsonArray([.. authorityHints.Select(h => (JsonNode?)h)]),
            ["metadata"] = new JsonObject { ["openid_relying_party"] = RpMetadata.DeepClone() },
        };

        /// <summary>Publishes a superior's entity configuration with a fetch endpoint.</summary>
        public void PublishSuperior(Entity entity, params string[] authorityHints)
        {
            var payload = new JsonObject
            {
                ["iss"] = entity.Id,
                ["sub"] = entity.Id,
                ["jwks"] = entity.Jwks(),
                ["metadata"] = new JsonObject
                {
                    ["federation_entity"] = new JsonObject { ["federation_fetch_endpoint"] = entity.Id + "/fetch" },
                },
            };
            if (authorityHints.Length > 0)
                payload["authority_hints"] = new JsonArray([.. authorityHints.Select(h => (JsonNode?)h)]);
            Web.Serve(entity.Id + "/.well-known/openid-federation", entity.Sign(payload), EntityStatement.MediaType);
        }

        /// <summary>Publishes <paramref name="superior"/>'s subordinate statement about <paramref name="subject"/>.</summary>
        public void PublishSubordinate(Entity superior, Entity subject, JsonObject? metadataPolicy = null,
            JsonObject? metadata = null, JsonObject? jwks = null)
        {
            var payload = new JsonObject
            {
                ["iss"] = superior.Id,
                ["sub"] = subject.Id,
                ["jwks"] = jwks ?? subject.Jwks(),
            };
            if (metadataPolicy is not null)
                payload["metadata_policy"] = new JsonObject { ["openid_relying_party"] = metadataPolicy };
            if (metadata is not null)
                payload["metadata"] = new JsonObject { ["openid_relying_party"] = metadata };
            Web.Serve($"{superior.Id}/fetch?sub={Uri.EscapeDataString(subject.Id)}", superior.Sign(payload), EntityStatement.MediaType);
        }

        public void PublishRp(params string[] authorityHints) =>
            Web.Serve(Rp + "/.well-known/openid-federation", RelyingParty.Sign(RpConfiguration(authorityHints)), EntityStatement.MediaType);

        /// <summary>RP directly below the trust anchor.</summary>
        public Federation Direct(JsonObject? policy = null)
        {
            PublishSuperior(TrustAnchor);
            PublishSubordinate(TrustAnchor, RelyingParty, policy);
            PublishRp(Anchor);
            return this;
        }

        public TestWebApp CreateApp(Action<ProviderOptions>? configure = null) => Web.CreateApp(o =>
        {
            o.FederationEnabled = true;
            o.FederationTrustAnchors[Anchor] = TrustAnchor.Jwks().ToJsonString();
            o.JarEnabled = true;
            configure?.Invoke(o);
        });
    }

    private static async Task<JsonWebToken> EntityConfigurationAsync(TestWebApp app)
    {
        var resp = await app.Client.GetAsync("/.well-known/openid-federation");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return new JsonWebToken(await resp.Content.ReadAsStringAsync());
    }

    private static Task<Abstractions.Models.Client?> FindClientAsync(TestWebApp app, string clientId) =>
        app.Services.GetRequiredService<IClientStore>().FindClientAsync(clientId);

    // ── Entity configuration ────────────────────────────────────────────────

    [Fact]
    public async Task EntityConfiguration_IsSignedWithFederationKey_NotProtocolKeys()
    {
        await using var app = TestWebApp.Create(o => o.FederationEnabled = true);
        var token = await EntityConfigurationAsync(app);

        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(token.EncodedPayload))!;
        var federationJwks = new JsonWebKeySet(payload["jwks"]!.ToJsonString());
        var opJwks = JsonNode.Parse(await app.Client.GetStringAsync("/.well-known/jwks.json"))!["keys"]!.AsArray();

        Assert.Contains(federationJwks.Keys, k => k.Kid == token.Kid);
        Assert.DoesNotContain(opJwks, k => (string?)k!["kid"] == token.Kid);
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(token.EncodedToken, new TokenValidationParameters
        {
            IssuerSigningKeys = federationJwks.GetSigningKeys(),
            ValidIssuer = Issuer,
            ValidateAudience = false,
            ValidTypes = ["entity-statement+jwt"],
        });
        Assert.True(validation.IsValid, validation.Exception?.Message);
    }

    [Fact]
    public async Task EntityConfiguration_OpenIdProviderMetadata_MatchesDiscovery()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.FederationEnabled = true;
            o.FederationEntityMetadata["organization_name"] = "Example Org";
        });
        var token = await EntityConfigurationAsync(app);
        var metadata = JsonNode.Parse(Base64UrlEncoder.Decode(token.EncodedPayload))!["metadata"]!;
        var discovery = JsonNode.Parse(await app.Client.GetStringAsync("/.well-known/openid-configuration"))!;

        var op = metadata["openid_provider"]!;
        foreach (var name in new[] { "issuer", "token_endpoint", "jwks_uri", "scopes_supported", "grant_types_supported" })
            Assert.True(JsonNode.DeepEquals(discovery[name], op[name]), name);
        Assert.Equal(Issuer + "/connect/federation_registration", (string?)op["federation_registration_endpoint"]);
        Assert.Equal(["automatic", "explicit"], op["client_registration_types_supported"]!.AsArray().Select(n => (string)n!));
        Assert.Equal("Example Org", (string?)metadata["federation_entity"]!["organization_name"]);
    }

    [Fact]
    public async Task Discovery_OmitsDisabledRegistrationTypes()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.FederationEnabled = true;
            o.FederationExplicitRegistrationEnabled = false;
        });
        var discovery = JsonNode.Parse(await app.Client.GetStringAsync("/.well-known/openid-configuration"))!;

        Assert.Equal(["automatic"], discovery["client_registration_types_supported"]!.AsArray().Select(n => (string)n!));
        Assert.Null(discovery["federation_registration_endpoint"]);
    }

    // ── Automatic registration ──────────────────────────────────────────────

    [Fact]
    public async Task AutomaticRegistration_ResolvesClientThroughTrustChain()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp();

        var client = await FindClientAsync(app, Rp);

        Assert.NotNull(client);
        Assert.Equal("private_key_jwt", client.TokenEndpointAuthMethod);
        Assert.True(client.RequireSignedRequestObject);
        Assert.True(client.RequireConsent);
        Assert.Equal(["https://rp.example.net/cb"], client.RedirectUris);
        Assert.Contains("rp-protocol", client.JwksJson);
        Assert.DoesNotContain(federation.RelyingParty.Key.KeyId!, client.JwksJson);
    }

    [Fact]
    public async Task AutomaticRegistration_ThroughIntermediate()
    {
        var federation = new Federation();
        federation.PublishSuperior(federation.TrustAnchor);
        federation.PublishSuperior(federation.Mid, Anchor);
        federation.PublishSubordinate(federation.TrustAnchor, federation.Mid);
        federation.PublishSubordinate(federation.Mid, federation.RelyingParty);
        federation.PublishRp(Intermediate);
        await using var app = federation.CreateApp();

        Assert.NotNull(await FindClientAsync(app, Rp));
    }

    [Fact]
    public async Task AutomaticRegistration_ChainLongerThanLimit_IsRejected()
    {
        var federation = new Federation();
        federation.PublishSuperior(federation.TrustAnchor);
        federation.PublishSuperior(federation.Mid, Anchor);
        federation.PublishSubordinate(federation.TrustAnchor, federation.Mid);
        federation.PublishSubordinate(federation.Mid, federation.RelyingParty);
        federation.PublishRp(Intermediate);
        await using var app = federation.CreateApp(o => o.FederationMaxChainLength = 1);

        Assert.Null(await FindClientAsync(app, Rp));
    }

    [Fact]
    public async Task AutomaticRegistration_UnknownTrustAnchorKey_IsRejected()
    {
        var federation = new Federation().Direct();
        var impostor = new Entity(Anchor);
        await using var app = federation.CreateApp(o => o.FederationTrustAnchors[Anchor] = impostor.Jwks().ToJsonString());

        Assert.Null(await FindClientAsync(app, Rp));
    }

    [Fact]
    public async Task AutomaticRegistration_SubordinateStatementWithOtherKeys_IsRejected()
    {
        // The superior vouches for different keys than the RP signs its configuration with.
        var federation = new Federation();
        federation.PublishSuperior(federation.TrustAnchor);
        federation.PublishSubordinate(federation.TrustAnchor, federation.RelyingParty, jwks: new Entity(Rp).Jwks());
        federation.PublishRp(Anchor);
        await using var app = federation.CreateApp();

        Assert.Null(await FindClientAsync(app, Rp));
    }

    [Fact]
    public async Task AutomaticRegistration_UnconfiguredAnchor_IsRejected()
    {
        var federation = new Federation().Direct();
        await using var app = federation.Web.CreateApp(o =>
        {
            o.FederationEnabled = true;
            o.JarEnabled = true;
            o.FederationTrustAnchors["https://other-ta.example.org"] = federation.TrustAnchor.Jwks().ToJsonString();
        });

        Assert.Null(await FindClientAsync(app, Rp));
    }

    [Fact]
    public async Task AutomaticRegistration_Disabled_DoesNotResolve()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp(o => o.FederationAutomaticRegistrationEnabled = false);

        Assert.Null(await FindClientAsync(app, Rp));
    }

    [Fact]
    public async Task AutomaticRegistration_AppliesMetadataPolicy()
    {
        var policy = new JsonObject
        {
            ["scope"] = new JsonObject { ["subset_of"] = new JsonArray("openid") },
            ["client_name"] = new JsonObject { ["value"] = "Renamed by TA" },
        };
        var federation = new Federation().Direct(policy);
        await using var app = federation.CreateApp();

        var client = await FindClientAsync(app, Rp);

        Assert.NotNull(client);
        Assert.Equal(["openid"], client.AllowedScopes);
        Assert.Equal("Renamed by TA", client.ClientName);
    }

    [Fact]
    public async Task AutomaticRegistration_PolicyViolation_IsRejected()
    {
        var policy = new JsonObject
        {
            ["token_endpoint_auth_method"] = new JsonObject { ["one_of"] = new JsonArray("self_signed_tls_client_auth") },
        };
        var federation = new Federation().Direct(policy);
        await using var app = federation.CreateApp();

        Assert.Null(await FindClientAsync(app, Rp));
    }

    [Fact]
    public async Task AutomaticRegistration_AuthorizationRequestWithoutRequestObject_IsRejected()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", Rp), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", "https://rp.example.net/cb"),
            ("code_challenge", Oidc.Challenge), ("code_challenge_method", "S256"));

        Oidc.AssertRedirectError(resp, "invalid_request");
    }

    [Fact]
    public async Task AutomaticRegistration_SignedRequestObject_ReachesInteraction()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp();
        await Oidc.SignInAsync(app, "alice");
        var request = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Rp,
            Audience = Issuer,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["client_id"] = Rp,
                ["response_type"] = "code",
                ["redirect_uri"] = "https://rp.example.net/cb",
                ["scope"] = "openid",
                ["state"] = "s1",
                ["code_challenge"] = Oidc.Challenge,
                ["code_challenge_method"] = "S256",
            },
            SigningCredentials = new SigningCredentials(federation.RpProtocolKey, SecurityAlgorithms.RsaSha256),
        });

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", Rp), ("request", request));

        // Automatically registered clients always need consent, so the End-User is sent to it.
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.DoesNotContain("error=", resp.Headers.Location!.ToString());
        Assert.False(resp.Headers.Location!.ToString().StartsWith("https://rp.example.net", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AutomaticRegistration_PolicyRemovingAllScopes_GrantsOnlyOpenId()
    {
        var policy = new JsonObject { ["scope"] = new JsonObject { ["subset_of"] = new JsonArray("email") } };
        var federation = new Federation().Direct(policy);
        await using var app = federation.CreateApp();

        var client = await FindClientAsync(app, Rp);

        Assert.NotNull(client);
        Assert.Equal(["openid"], client.AllowedScopes);
    }

    // ── Explicit registration ───────────────────────────────────────────────

    private static async Task<HttpResponseMessage> RegisterAsync(TestWebApp app, string body, string mediaType = EntityStatement.MediaType)
    {
        var content = new StringContent(body, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        return await app.Client.PostAsync("/connect/federation_registration", content);
    }

    private static string RegistrationRequest(Federation federation, string audience = Issuer)
    {
        var payload = federation.RpConfiguration(Anchor);
        payload["aud"] = audience;
        return federation.RelyingParty.Sign(payload);
    }

    [Fact]
    public async Task ExplicitRegistration_RegistersClient_AndReturnsSignedResponse()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp(o => o.FederationAutomaticRegistrationEnabled = false);

        var resp = await RegisterAsync(app, RegistrationRequest(federation));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/explicit-registration-response+jwt", resp.Content.Headers.ContentType?.MediaType);
        var response = new JsonWebToken(await resp.Content.ReadAsStringAsync());
        Assert.Equal("explicit-registration-response+jwt", response.Typ);

        // Signed with the OP's federation key, as published in its entity configuration.
        var configuration = await EntityConfigurationAsync(app);
        var jwks = new JsonWebKeySet(JsonNode.Parse(Base64UrlEncoder.Decode(configuration.EncodedPayload))!["jwks"]!.ToJsonString());
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(response.EncodedToken, new TokenValidationParameters
        {
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidIssuer = Issuer,
            ValidAudience = Rp,
            ValidTypes = ["explicit-registration-response+jwt"],
        });
        Assert.True(validation.IsValid, validation.Exception?.Message);

        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(response.EncodedPayload))!;
        Assert.Equal(Rp, (string?)payload["sub"]);
        Assert.Equal(Anchor, (string?)payload["trust_anchor"]);
        Assert.Equal(Rp, (string?)payload["metadata"]!["openid_relying_party"]!["client_id"]);

        var client = await FindClientAsync(app, Rp);
        Assert.NotNull(client);
        Assert.False(client.RequireSignedRequestObject);
    }

    [Fact]
    public async Task ExplicitRegistration_WrongAudience_IsRejected()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp();

        var resp = await RegisterAsync(app, RegistrationRequest(federation, "https://other-op.example.com"));

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task ExplicitRegistration_WrongContentType_IsRejected()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp();

        var resp = await RegisterAsync(app, RegistrationRequest(federation), "application/json");

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task ExplicitRegistration_ForgedRequest_IsRejected()
    {
        // Signed by a key the trust anchor never vouched for.
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp();
        var payload = federation.RpConfiguration(Anchor);
        payload["aud"] = Issuer;
        var forger = new Entity(Rp);
        payload["jwks"] = forger.Jwks();

        var resp = await RegisterAsync(app, forger.Sign(payload));

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
        Assert.Null(await app.Services.GetRequiredService<IAdapter<Abstractions.Models.Client>>()
            .FindAsync(Adapters.ResolvingClientStore.CachePrefix + Rp));
    }

    [Fact]
    public async Task ExplicitRegistration_StaticClientId_IsNotReplaced()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp(o => o.StaticClients =
        [
            .. o.StaticClients,
            new Abstractions.Models.Client { ClientId = Rp, ClientSecret = "s", RedirectUris = ["https://rp.example.net/cb"] },
        ]);

        var resp = await RegisterAsync(app, RegistrationRequest(federation));

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task ExplicitRegistration_Disabled_Returns404()
    {
        var federation = new Federation().Direct();
        await using var app = federation.CreateApp(o => o.FederationExplicitRegistrationEnabled = false);

        var resp = await RegisterAsync(app, RegistrationRequest(federation));

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public void Options_AutomaticRegistrationWithoutJar_FailsValidation()
    {
        var options = new ProviderOptions { Issuer = Issuer, FederationEnabled = true };
        options.FederationTrustAnchors[Anchor] = new Entity(Anchor).Jwks().ToJsonString();
        options.FederationTrustAnchors["http://insecure.example.org"] = "not a jwks";

        var result = new ProviderOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("requires JarEnabled"));
        Assert.Contains(result.Failures!, f => f.Contains("must be an https entity identifier"));
        Assert.Contains(result.Failures!, f => f.Contains("must map to a JWKS"));
    }

    // ── Metadata policy operators ───────────────────────────────────────────

    private static JsonObject Obj(string json) => JsonNode.Parse(json)!.AsObject();

    [Fact]
    public void MetadataPolicy_ValueAddDefault()
    {
        var metadata = Obj("""{"a":"x","b":["1"]}""");
        var error = MetadataPolicy.Apply(metadata, Obj("""{"a":{"value":"y"},"b":{"add":["2"]},"c":{"default":"d"}}"""));

        Assert.Null(error);
        Assert.True(JsonNode.DeepEquals(Obj("""{"a":"y","b":["1","2"],"c":"d"}"""), metadata));
    }

    [Fact]
    public void MetadataPolicy_SubsetOf_Intersects_AndSupersetOf_Requires()
    {
        var metadata = Obj("""{"s":["a","b","c"]}""");
        Assert.Null(MetadataPolicy.Apply(metadata, Obj("""{"s":{"subset_of":["a","c","z"]}}""")));
        Assert.True(JsonNode.DeepEquals(Obj("""{"s":["a","c"]}"""), metadata));

        Assert.NotNull(MetadataPolicy.Apply(metadata, Obj("""{"s":{"superset_of":["b"]}}""")));
    }

    [Fact]
    public void MetadataPolicy_OneOf_Essential_AndUnknownOperator()
    {
        Assert.NotNull(MetadataPolicy.Apply(Obj("""{"m":"x"}"""), Obj("""{"m":{"one_of":["y"]}}""")));
        Assert.Null(MetadataPolicy.Apply(Obj("""{"m":"y"}"""), Obj("""{"m":{"one_of":["y"]}}""")));
        Assert.NotNull(MetadataPolicy.Apply(Obj("{}"), Obj("""{"m":{"essential":true}}""")));
        Assert.NotNull(MetadataPolicy.Apply(Obj("{}"), Obj("""{"m":{"regexp":"."}}""")));
    }
}
