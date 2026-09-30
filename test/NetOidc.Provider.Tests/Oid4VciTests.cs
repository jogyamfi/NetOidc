using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Vci;

namespace NetOidc.Provider.Tests;

/// <summary>OID4VCI 1.0 final (P5.4): offers, pre-authorized codes, authorization details, deferral, notifications.</summary>
public sealed class Oid4VciTests
{
    private const string Issuer = "https://auth.test.example.com";
    private const string PreAuthGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    private static TestWebApp CreateApp(Action<ProviderOptions>? configure = null) => TestWebApp.Create(o =>
    {
        o.VciEnabled = true;
        o.VciPreAuthorizedAnonymousAccess = true;
        o.Scopes = [.. o.Scopes, new Scope { Name = "degree" }];
        o.VciCredentialConfigurations.Add(new CredentialConfiguration { Id = "Degree", Format = "jwt_vc_json", Scope = "degree" });
        o.VciCredentialConfigurations.Add(new CredentialConfiguration { Id = "Badge", Format = "jwt_vc_json" });
        o.IssueCredential = (req, _) => Task.FromResult(CredentialIssuanceResult.Issued(
            [.. req.HolderPublicJwks.Select((_, i) => $"{req.CredentialConfigurationId}-{i}").DefaultIfEmpty(req.CredentialConfigurationId)]));
        configure?.Invoke(o);
    });

    private static Task<CreatedCredentialOffer> OfferAsync(TestWebApp app, TxCodeOptions? txCode = null, params string[] ids) =>
        app.Services.GetRequiredService<CredentialOfferService>().CreateAsync(new CredentialOfferRequest
        {
            CredentialConfigurationIds = ids.Length == 0 ? ["Badge"] : ids,
            PreAuthorizedSubject = "alice",
            TxCode = txCode,
        });

    private static Task<HttpResponseMessage> PreAuthTokenAsync(TestWebApp app, string code, string? txCode = null,
        AuthenticationHeaderValue? auth = null, string? clientId = null)
    {
        var form = new List<KeyValuePair<string, string>> { new("grant_type", PreAuthGrant), new("pre-authorized_code", code) };
        if (txCode is not null) form.Add(new("tx_code", txCode));
        if (clientId is not null) form.Add(new("client_id", clientId));
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token") { Content = new FormUrlEncodedContent(form) };
        request.Headers.Authorization = auth;
        return app.Client.SendAsync(request);
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage resp, HttpStatusCode expected = HttpStatusCode.OK)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == expected, $"{(int)resp.StatusCode}: {body}");
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    private static async Task<string> AnonymousTokenAsync(TestWebApp app, params string[] ids)
    {
        var offer = await OfferAsync(app, null, ids);
        return (await JsonAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!))).GetProperty("access_token").GetString()!;
    }

    private static async Task<string> NonceAsync(TestWebApp app) =>
        (await JsonAsync(await app.Client.PostAsync("/connect/nonce", null))).GetProperty("c_nonce").GetString()!;

    private static string Proof(ECDsa key, string nonce)
    {
        var p = key.ExportParameters(false);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = Issuer,
            IssuedAt = DateTime.UtcNow,
            TokenType = "openid4vci-proof+jwt",
            Claims = new Dictionary<string, object> { ["nonce"] = nonce },
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, object>
                {
                    ["kty"] = "EC", ["crv"] = "P-256",
                    ["x"] = Base64UrlEncoder.Encode(p.Q.X!), ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
                },
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
        });
    }

    private static async Task<HttpResponseMessage> PostJsonAsync(TestWebApp app, string path, string token, object body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await app.Client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> CredentialAsync(TestWebApp app, string token, int proofs = 1,
        string? identifier = "Badge", string? configurationId = null, object? extra = null)
    {
        var jwts = new List<string>();
        for (var i = 0; i < proofs; i++)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            jwts.Add(Proof(key, await NonceAsync(app)));
        }
        var body = new Dictionary<string, object> { ["proofs"] = new { jwt = jwts } };
        if (identifier is not null) body["credential_identifier"] = identifier;
        if (configurationId is not null) body["credential_configuration_id"] = configurationId;
        if (extra is not null) body["credential_response_encryption"] = extra;
        return await PostJsonAsync(app, "/connect/credential", token, body);
    }

    private static async Task AssertErrorAsync(HttpResponseMessage resp, HttpStatusCode status, string error) =>
        Assert.Equal(error, (await JsonAsync(resp, status)).GetProperty("error").GetString());

    // ── Credential offer ────────────────────────────────────────────────────

    [Fact]
    public async Task Offer_IsServedByReference()
    {
        await using var app = CreateApp();
        var offer = await OfferAsync(app, new TxCodeOptions(Description: "Sent by SMS"));

        Assert.StartsWith("openid-credential-offer://?credential_offer_uri=", offer.OfferUri);
        Assert.Equal(offer.CredentialOfferUri, HttpUtility.ParseQueryString(new Uri(offer.OfferUri).Query)["credential_offer_uri"]);
        Assert.Matches("^[0-9]{6}$", offer.TxCode);

        var served = await JsonAsync(await app.Client.GetAsync(new Uri(offer.CredentialOfferUri).AbsolutePath));
        Assert.Equal(Issuer, served.GetProperty("credential_issuer").GetString());
        Assert.Equal("Badge", served.GetProperty("credential_configuration_ids")[0].GetString());
        var grant = served.GetProperty("grants").GetProperty(PreAuthGrant);
        Assert.Equal(offer.PreAuthorizedCode, grant.GetProperty("pre-authorized_code").GetString());
        Assert.Equal(6, grant.GetProperty("tx_code").GetProperty("length").GetInt32());
        Assert.DoesNotContain(offer.TxCode!, served.GetRawText());
    }

    [Fact]
    public async Task Offer_UnknownId_Returns404()
    {
        await using var app = CreateApp();
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync("/connect/credential_offer/nope")).StatusCode);
    }

    [Fact]
    public async Task Offer_UnknownConfiguration_Throws()
    {
        await using var app = CreateApp();
        await Assert.ThrowsAsync<ArgumentException>(() => OfferAsync(app, null, "Unknown"));
    }

    // ── Pre-authorized code grant ───────────────────────────────────────────

    [Fact]
    public async Task PreAuthorizedCode_AnonymousFlow_IssuesCredentials()
    {
        await using var app = CreateApp();
        var offer = await OfferAsync(app, new TxCodeOptions());

        var token = await JsonAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!, offer.TxCode));
        Assert.False(token.TryGetProperty("id_token", out _));
        Assert.False(token.TryGetProperty("refresh_token", out _));
        var details = token.GetProperty("authorization_details")[0];
        Assert.Equal("openid_credential", details.GetProperty("type").GetString());
        Assert.Equal("Badge", details.GetProperty("credential_identifiers")[0].GetString());

        var credential = await JsonAsync(await CredentialAsync(app, token.GetProperty("access_token").GetString()!));
        Assert.Equal("Badge-0", credential.GetProperty("credentials")[0].GetProperty("credential").GetString());
    }

    [Fact]
    public async Task PreAuthorizedCode_IsSingleUse()
    {
        await using var app = CreateApp();
        var offer = await OfferAsync(app);

        await JsonAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!));
        await AssertErrorAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!), HttpStatusCode.BadRequest, "invalid_grant");
    }

    [Fact]
    public async Task PreAuthorizedCode_TxCodeChecks()
    {
        await using var app = CreateApp(o => o.VciTxCodeMaxAttempts = 2);
        var offer = await OfferAsync(app, new TxCodeOptions());

        await AssertErrorAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!), HttpStatusCode.BadRequest, "invalid_request");
        await AssertErrorAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!, "000000x"), HttpStatusCode.BadRequest, "invalid_grant");
        await AssertErrorAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!, "111111x"), HttpStatusCode.BadRequest, "invalid_grant");

        // Attempts exhausted: the code is revoked, even for the right transaction code.
        await AssertErrorAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!, offer.TxCode), HttpStatusCode.BadRequest, "invalid_grant");
    }

    [Fact]
    public async Task PreAuthorizedCode_UnexpectedTxCode_IsRejected()
    {
        await using var app = CreateApp();
        var offer = await OfferAsync(app);

        await AssertErrorAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!, "123456"), HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task PreAuthorizedCode_WithoutAnonymousAccess_RequiresClient()
    {
        await using var app = CreateApp(o => o.VciPreAuthorizedAnonymousAccess = false);
        var offer = await OfferAsync(app);

        Assert.Equal(HttpStatusCode.Unauthorized, (await PreAuthTokenAsync(app, offer.PreAuthorizedCode!)).StatusCode);
    }

    [Fact]
    public async Task PreAuthorizedCode_ClientWithoutGrant_IsRejected()
    {
        await using var app = CreateApp();
        var offer = await OfferAsync(app);

        var resp = await PreAuthTokenAsync(app, offer.PreAuthorizedCode!, auth: Oidc.Basic("test-client", "test-secret"));

        await AssertErrorAsync(resp, HttpStatusCode.BadRequest, "unauthorized_client");
    }

    [Fact]
    public async Task PreAuthorizedCode_WalletClient_GetsTokenForItself()
    {
        await using var app = CreateApp(o => o.StaticClients = [.. o.StaticClients, new Client
        {
            ClientId = "wallet",
            TokenEndpointAuthMethod = "none",
            AllowedGrantTypes = [PreAuthGrant],
            RequireConsent = false,
        }]);
        var offer = await OfferAsync(app);

        var token = await JsonAsync(await PreAuthTokenAsync(app, offer.PreAuthorizedCode!, clientId: "wallet"));

        var introspected = app.Services.GetRequiredService<Token.AccessTokenService>();
        var live = await introspected.ValidateAsync(token.GetProperty("access_token").GetString()!, default);
        Assert.Equal("wallet", live!.Record.ClientId);
        Assert.Equal("alice", live.Record.Subject);
    }

    // ── Credential request rules ────────────────────────────────────────────

    [Fact]
    public async Task Credential_ByConfigurationId_WhenTokenListsIdentifiers_IsRejected()
    {
        await using var app = CreateApp();
        var token = await AnonymousTokenAsync(app);

        await AssertErrorAsync(await CredentialAsync(app, token, identifier: null, configurationId: "Badge"),
            HttpStatusCode.BadRequest, "invalid_credential_request");
    }

    [Fact]
    public async Task Credential_UnknownIdentifier_IsRejected()
    {
        await using var app = CreateApp();
        var token = await AnonymousTokenAsync(app);

        await AssertErrorAsync(await CredentialAsync(app, token, identifier: "Degree"),
            HttpStatusCode.BadRequest, "unknown_credential_identifier");
    }

    [Fact]
    public async Task Credential_BothIdentifierAndConfiguration_IsRejected()
    {
        await using var app = CreateApp();
        var token = await AnonymousTokenAsync(app);

        await AssertErrorAsync(await CredentialAsync(app, token, identifier: "Badge", configurationId: "Badge"),
            HttpStatusCode.BadRequest, "invalid_credential_request");
    }

    [Fact]
    public async Task Credential_ConfigurationWithoutScope_NeedsAuthorizationDetails()
    {
        // Before P5.4 a configuration without a scope was issued to any End-User token.
        await using var app = CreateApp();
        var token = await app.IssueUserAccessTokenAsync("alice", "test-client", "openid", "degree");

        await AssertErrorAsync(await CredentialAsync(app, token, identifier: null, configurationId: "Badge"),
            HttpStatusCode.Forbidden, "insufficient_scope");
        await JsonAsync(await CredentialAsync(app, token, identifier: null, configurationId: "Degree"));
    }

    [Fact]
    public async Task Credential_ResponseEncryption_IsRejected()
    {
        await using var app = CreateApp();
        var token = await AnonymousTokenAsync(app);

        await AssertErrorAsync(await CredentialAsync(app, token, extra: new { enc = "A128GCM" }),
            HttpStatusCode.BadRequest, "invalid_encryption_parameters");
    }

    [Fact]
    public async Task Credential_Batch_IssuesOnePerProof_UpToBatchSize()
    {
        await using var app = CreateApp(o => o.VciBatchSize = 2);
        var token = await AnonymousTokenAsync(app);

        var credentials = (await JsonAsync(await CredentialAsync(app, token, proofs: 2))).GetProperty("credentials");
        Assert.Equal(2, credentials.GetArrayLength());

        await AssertErrorAsync(await CredentialAsync(app, token, proofs: 3), HttpStatusCode.BadRequest, "invalid_proof");
    }

    [Fact]
    public async Task Credential_HookReturningWrongCount_IsServerError()
    {
        await using var app = CreateApp(o =>
        {
            o.VciBatchSize = 2;
            o.IssueCredential = (_, _) => Task.FromResult<CredentialIssuanceResult>("only-one");
        });
        var token = await AnonymousTokenAsync(app);

        Assert.Equal(HttpStatusCode.InternalServerError, (await CredentialAsync(app, token, proofs: 2)).StatusCode);
    }

    // ── authorization_details at the authorization endpoint ─────────────────

    [Fact]
    public async Task AuthorizationCode_WithCredentialAuthorizationDetails_ReturnsIdentifiers()
    {
        await using var app = CreateApp();
        var details = """[{"type":"openid_credential","credential_configuration_id":"Badge"}]""";

        var token = await Oidc.CodeFlowAsync(app, extra: ("authorization_details", details));

        Assert.Equal("Badge", token.GetProperty("authorization_details")[0].GetProperty("credential_identifiers")[0].GetString());
        var credential = await JsonAsync(await CredentialAsync(app, token.GetProperty("access_token").GetString()!));
        Assert.Equal("Badge-0", credential.GetProperty("credentials")[0].GetProperty("credential").GetString());
    }

    [Theory]
    [InlineData("""[{"type":"openid_credential","credential_configuration_id":"Unknown"}]""")]
    [InlineData("""[{"type":"openid_credential"}]""")]
    [InlineData("""[{"type":"payment_initiation"}]""")]
    [InlineData("""[{"type":7}]""")]
    public async Task AuthorizationCode_InvalidCredentialAuthorizationDetails_AreRejected(string details)
    {
        await using var app = CreateApp();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", Oidc.Callback), ("authorization_details", details));

        Oidc.AssertRedirectError(resp, "invalid_authorization_details");
    }

    // ── Deferred issuance ───────────────────────────────────────────────────

    [Fact]
    public async Task Deferred_IssuanceCompletesAtDeferredEndpoint()
    {
        var ready = false;
        await using var app = CreateApp(o =>
        {
            o.IssueCredential = (_, _) => Task.FromResult(CredentialIssuanceResult.Deferred(TimeSpan.FromSeconds(5)));
            o.RetrieveDeferredCredential = (req, _) => Task.FromResult(ready
                ? CredentialIssuanceResult.Issued($"late-{req.Request.CredentialConfigurationId}")
                : CredentialIssuanceResult.Deferred(TimeSpan.FromSeconds(3)));
        });
        var token = await AnonymousTokenAsync(app);

        var pending = await JsonAsync(await CredentialAsync(app, token), HttpStatusCode.Accepted);
        var transactionId = pending.GetProperty("transaction_id").GetString()!;
        Assert.Equal(5, pending.GetProperty("interval").GetInt32());

        var stillPending = await JsonAsync(await PostJsonAsync(app, "/connect/deferred_credential", token,
            new { transaction_id = transactionId }), HttpStatusCode.Accepted);
        Assert.Equal(3, stillPending.GetProperty("interval").GetInt32());

        ready = true;
        var issued = await JsonAsync(await PostJsonAsync(app, "/connect/deferred_credential", token, new { transaction_id = transactionId }));
        Assert.Equal("late-Badge", issued.GetProperty("credentials")[0].GetProperty("credential").GetString());

        await AssertErrorAsync(await PostJsonAsync(app, "/connect/deferred_credential", token, new { transaction_id = transactionId }),
            HttpStatusCode.BadRequest, "invalid_transaction_id");
    }

    [Fact]
    public async Task Deferred_TransactionOfAnotherEndUser_IsRejected()
    {
        await using var app = CreateApp(o =>
        {
            o.IssueCredential = (_, _) => Task.FromResult(CredentialIssuanceResult.Deferred(TimeSpan.FromSeconds(5)));
            o.RetrieveDeferredCredential = (_, _) => Task.FromResult<CredentialIssuanceResult>("stolen");
        });
        var pending = await JsonAsync(await CredentialAsync(app, await AnonymousTokenAsync(app)), HttpStatusCode.Accepted);
        var other = await app.IssueUserAccessTokenAsync("mallory", CredentialOfferService.AnonymousClientId, "degree");

        await AssertErrorAsync(await PostJsonAsync(app, "/connect/deferred_credential", other,
            new { transaction_id = pending.GetProperty("transaction_id").GetString() }), HttpStatusCode.BadRequest, "invalid_transaction_id");
    }

    [Fact]
    public async Task Deferred_WithoutRetrievalHook_IsServerError()
    {
        await using var app = CreateApp(o =>
            o.IssueCredential = (_, _) => Task.FromResult(CredentialIssuanceResult.Deferred(TimeSpan.FromSeconds(5))));

        Assert.Equal(HttpStatusCode.InternalServerError, (await CredentialAsync(app, await AnonymousTokenAsync(app))).StatusCode);
    }

    // ── Notifications ───────────────────────────────────────────────────────

    [Fact]
    public async Task Notification_IsDeliveredToHook()
    {
        var received = new ConcurrentQueue<CredentialNotification>();
        await using var app = CreateApp(o => o.OnCredentialNotification = (n, _) =>
        {
            received.Enqueue(n);
            return Task.CompletedTask;
        });
        var token = await AnonymousTokenAsync(app);
        var notificationId = (await JsonAsync(await CredentialAsync(app, token))).GetProperty("notification_id").GetString()!;

        var resp = await PostJsonAsync(app, "/connect/notification", token,
            new { notification_id = notificationId, @event = "credential_accepted", event_description = "stored" });

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        var notification = Assert.Single(received);
        Assert.Equal(("credential_accepted", "stored", "alice", "Badge"),
            (notification.Event, notification.EventDescription, notification.Subject, notification.CredentialConfigurationId));
    }

    [Fact]
    public async Task Notification_InvalidRequests_AreRejected()
    {
        await using var app = CreateApp(o => o.OnCredentialNotification = (_, _) => Task.CompletedTask);
        var token = await AnonymousTokenAsync(app);
        var notificationId = (await JsonAsync(await CredentialAsync(app, token))).GetProperty("notification_id").GetString()!;

        await AssertErrorAsync(await PostJsonAsync(app, "/connect/notification", token,
            new { notification_id = notificationId, @event = "credential_lost" }), HttpStatusCode.BadRequest, "invalid_notification_request");
        await AssertErrorAsync(await PostJsonAsync(app, "/connect/notification", token,
            new { notification_id = "unknown", @event = "credential_accepted" }), HttpStatusCode.BadRequest, "invalid_notification_id");

        var other = await app.IssueUserAccessTokenAsync("mallory", CredentialOfferService.AnonymousClientId, "degree");
        await AssertErrorAsync(await PostJsonAsync(app, "/connect/notification", other,
            new { notification_id = notificationId, @event = "credential_deleted" }), HttpStatusCode.BadRequest, "invalid_notification_id");
    }

    [Fact]
    public async Task Notification_WithoutHook_IsNotOffered()
    {
        await using var app = CreateApp();
        var token = await AnonymousTokenAsync(app);

        Assert.False((await JsonAsync(await CredentialAsync(app, token))).TryGetProperty("notification_id", out _));
        Assert.Equal(HttpStatusCode.NotFound, (await PostJsonAsync(app, "/connect/notification", token,
            new { notification_id = "x", @event = "credential_accepted" })).StatusCode);
    }

    // ── Issuer metadata ─────────────────────────────────────────────────────

    [Fact]
    public async Task IssuerMetadata_AdvertisesOnlyConfiguredFeatures()
    {
        await using var plain = CreateApp();
        var metadata = await JsonAsync(await plain.Client.GetAsync("/.well-known/openid-credential-issuer"));
        foreach (var absent in new[] { "deferred_credential_endpoint", "notification_endpoint", "batch_credential_issuance", "authorization_servers" })
            Assert.False(metadata.TryGetProperty(absent, out _), absent);
        Assert.False(metadata.GetProperty("credential_configurations_supported").GetProperty("Badge").TryGetProperty("scope", out _));

        await using var full = CreateApp(o =>
        {
            o.VciBatchSize = 3;
            o.VciCredentialIssuer = "https://credentials.example.com";
            o.RetrieveDeferredCredential = (_, _) => Task.FromResult<CredentialIssuanceResult>("x");
            o.OnCredentialNotification = (_, _) => Task.CompletedTask;
        });
        metadata = await JsonAsync(await full.Client.GetAsync("/.well-known/openid-credential-issuer"));
        Assert.Equal("https://credentials.example.com/connect/deferred_credential", metadata.GetProperty("deferred_credential_endpoint").GetString());
        Assert.Equal("https://credentials.example.com/connect/notification", metadata.GetProperty("notification_endpoint").GetString());
        Assert.Equal(3, metadata.GetProperty("batch_credential_issuance").GetProperty("batch_size").GetInt32());
        Assert.Equal(Issuer, metadata.GetProperty("authorization_servers")[0].GetString());
    }
}
