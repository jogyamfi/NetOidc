using System.Net;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Defects found by running the OpenID Foundation conformance suite against NetOidc
/// (REMEDIATION_PLAN P6.2). Each test failed before its fix.
/// </summary>
public sealed class ConformanceSuiteFindingsTests
{
    // ── Early authorization errors use the requested response mode ─────────

    [Fact]
    public async Task EarlyError_ForImplicitRequest_IsReturnedInTheFragment()
    {
        // JAR is off: the request object is refused before the response mode is resolved.
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "implicit-client"), ("response_type", "id_token"),
            ("scope", "openid"), ("nonce", "n"), ("state", "s1"), ("redirect_uri", Oidc.Callback), ("request", "e30.e30."));

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!;
        Assert.Empty(location.Query);
        Assert.Contains("error=request_not_supported", location.Fragment);
        Assert.Contains("state=s1", location.Fragment);
    }

    [Fact]
    public async Task EarlyError_WithFormPost_IsPosted()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        // response_type is missing, so the default mode cannot be derived from it.
        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("scope", "openid"),
            ("state", "s2"), ("redirect_uri", Oidc.Callback), ("response_mode", "form_post"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("method=\"post\"", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("unsupported_response_type", html);
        Assert.Contains("s2", html);
    }

    [Fact]
    public async Task UnsupportedRequestObject_ErrorFollowsItsResponseModeAndState()
    {
        // JAR is off. response_mode and state exist only inside the (unsigned) request object.
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");
        var payload = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            """{"response_mode":"form_post","state":"s3","response_type":"code","scope":"openid"}""");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"),
            ("scope", "openid"), ("redirect_uri", Oidc.Callback), ("request", $"eyJhbGciOiJub25lIn0.{payload}."));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("request_not_supported", html);
        Assert.Contains("s3", html);
    }

    // ── FAPI 1.0 Advanced: s_hash in front-channel ID tokens ────────────────

    [Fact]
    public async Task HybridIdToken_CarriesStateHash()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "hybrid-client"), ("response_type", "code id_token"),
            ("scope", "openid"), ("nonce", "n"), ("state", "state-123"), ("redirect_uri", Oidc.Callback));
        var idToken = Oidc.Jwt(Oidc.ResponseParams(resp)["id_token"]!);

        var expected = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes("state-123"))[..16]);
        Assert.Equal(expected, idToken.GetClaim("s_hash").Value);
    }

    // ── CIBA grant type (CIBA Core 1.0 §10.1) ──────────────────────────────

    [Fact]
    public async Task Ciba_UsesTheRegisteredGrantTypeUrn()
    {
        await using var app = TestWebApp.Create(o => o.CibaEnabled = true);
        var discovery = JsonDocument.Parse(await app.Client.GetStringAsync("/.well-known/openid-configuration")).RootElement;

        var grants = discovery.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("urn:openid:params:grant-type:ciba", grants);
        Assert.DoesNotContain("urn:ietf:params:oauth:grant-type:ciba", grants);
    }

    [Fact]
    public async Task RequestObjectWithoutExp_IsAcceptedOutsideFapi()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var jwk = Microsoft.IdentityModel.Tokens.JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa.ExportParameters(false)));
        await using var app = TestWebApp.Create(o =>
        {
            o.JarEnabled = true;
            o.StaticClients =
            [
                .. o.StaticClients,
                new Abstractions.Models.Client
                {
                    ClientId = "jar-rp", ClientSecret = "jar-rp-secret", AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"], RedirectUris = [Oidc.Callback], RequirePkce = false, RequireConsent = false,
                    JwksJson = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", n = jwk.N, e = jwk.E } } }),
                },
            ];
        });
        var requestObject = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }
            .CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Issuer = "jar-rp",
                Audience = "https://auth.test.example.com",
                Claims = new Dictionary<string, object>
                {
                    ["client_id"] = "jar-rp", ["response_type"] = "code", ["scope"] = "openid", ["redirect_uri"] = Oidc.Callback,
                },
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                    new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa), "RS256"),
            });
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "jar-rp"), ("response_type", "code"),
            ("scope", "openid"), ("request", requestObject));

        Assert.NotNull(Oidc.ResponseParams(resp)["code"]);
    }

    // ── Expired device codes and CIBA requests (RFC 8628 §3.5, CIBA Core §11) ──

    [Fact]
    public async Task ExpiredCibaRequest_IsExpiredToken()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.CibaEnabled = true;
            o.CibaPollingIntervalSeconds = 0;
        });
        var start = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = Oidc.Basic("ciba-client", "ciba-secret") },
            Content = new FormUrlEncodedContent([new("scope", "openid"), new("login_hint", "alice"), new("requested_expiry", "1")]),
        });
        var authReqId = JsonDocument.Parse(await start.Content.ReadAsStringAsync()).RootElement.GetProperty("auth_req_id").GetString()!;
        await Task.Delay(1500);

        var resp = await Oidc.TokenAsync(app,
            [new("grant_type", "urn:openid:params:grant-type:ciba"), new("auth_req_id", authReqId)], ("ciba-client", "ciba-secret"));

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "expired_token");
    }

    [Fact]
    public async Task ExpiredDeviceCode_IsExpiredToken()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DeviceFlowEnabled = true;
            o.DeviceCodeLifetimeSeconds = 1;
            o.DevicePollingIntervalSeconds = 0;
        });
        var start = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = Oidc.Basic("device-client", "device-secret") },
            Content = new FormUrlEncodedContent([new("scope", "openid")]),
        });
        var deviceCode = JsonDocument.Parse(await start.Content.ReadAsStringAsync()).RootElement.GetProperty("device_code").GetString()!;
        await Task.Delay(1500);

        var resp = await Oidc.TokenAsync(app,
            [new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), new("device_code", deviceCode)], ("device-client", "device-secret"));

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "expired_token");
    }

    [Fact]
    public async Task Fapi_EchoesTheInteractionId()
    {
        await using var app = TestWebApp.Create(o => o.FapiProfile = FapiProfile.Fapi1Advanced);
        var id = Guid.NewGuid().ToString();
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Add("x-fapi-interaction-id", id);

        var echoed = await app.Client.SendAsync(request);
        var generated = await app.Client.GetAsync("/connect/userinfo");

        Assert.Equal(id, echoed.Headers.GetValues("x-fapi-interaction-id").Single());
        Assert.True(Guid.TryParse(generated.Headers.GetValues("x-fapi-interaction-id").Single(), out _));
    }

    // ── FAPI 2.0 suite findings ────────────────────────────────────────────

    [Fact]
    public async Task ErrorResponses_OmitNullDescription()
    {
        await using var app = TestWebApp.Create();
        var resp = await Oidc.TokenAsync(app, [new("grant_type", "client_credentials")], ("cc-client", "wrong"));
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
        // RFC 6749 §5.2: a string when present, never null.
        Assert.False(body.TryGetProperty("error_description", out _));
    }

    [Fact]
    public async Task AuthorizationErrors_CarryTheIssuer()
    {
        // RFC 9207 §2: iss is part of every authorization response, errors included.
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"),
            ("scope", "openid unknown-scope"), ("redirect_uri", Oidc.Callback));

        var response = Oidc.ResponseParams(resp);
        Assert.Equal("invalid_scope", response["error"]);
        Assert.Equal("https://auth.test.example.com", response["iss"]);
    }

    [Fact]
    public async Task UnsupportedResponseType_WithJarm_IsSignedInTheQuery()
    {
        await using var app = TestWebApp.Create(o => o.JarmEnabled = true);
        await Oidc.SignInAsync(app, "alice");

        // An unsupported response type has no default mode of its own: the JARM error goes where
        // the server's default (code) puts it, the query.
        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "bogus"),
            ("scope", "openid"), ("state", "s5"), ("redirect_uri", Oidc.Callback), ("response_mode", "jwt"));

        var location = resp.Headers.Location!;
        Assert.Empty(location.Fragment);
        var jarm = Oidc.Jwt(Oidc.ResponseParams(resp)["response"]!);
        Assert.Equal("unsupported_response_type", jarm.GetClaim("error").Value);
        Assert.Equal("s5", jarm.GetClaim("state").Value);
    }

    [Fact]
    public async Task Par_RejectsUnsupportedOrUnregisteredResponseTypes()
    {
        // RFC 9126 §2.1: the pushed request is validated as at the authorization endpoint.
        await using var app = TestWebApp.Create(o => o.PushedAuthorizationEnabled = true);

        Task<HttpResponseMessage> PushAsync(string responseType) =>
            app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/par")
            {
                Headers = { Authorization = Oidc.Basic("par-client", "par-secret") },
                Content = new FormUrlEncodedContent(
                [
                    new("response_type", responseType), new("scope", "openid"), new("nonce", "n"), new("redirect_uri", Oidc.Callback),
                ]),
            });

        await Oidc.AssertErrorAsync(await PushAsync("bogus"), HttpStatusCode.BadRequest, "unsupported_response_type");
        await Oidc.AssertErrorAsync(await PushAsync("code id_token"), HttpStatusCode.BadRequest, "unauthorized_client");
    }

    [Fact]
    public async Task MissingCodeVerifier_IsInvalidGrant()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");
        var authz = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"),
            ("scope", "openid"), ("redirect_uri", Oidc.Callback),
            ("code_challenge", Oidc.Challenge), ("code_challenge_method", "S256"));

        var resp = await Oidc.TokenAsync(app,
            [new("grant_type", "authorization_code"), new("code", Oidc.ResponseParams(authz)["code"]!), new("redirect_uri", Oidc.Callback)],
            ("test-client", "test-secret"));

        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_grant");
    }

    [Fact]
    public async Task ResponseTypeOutsideTheProfile_IsUnsupported()
    {
        await using var app = TestWebApp.Create(o => o.FapiProfile = FapiProfile.Fapi2Security);
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app, ("client_id", "hybrid-client"), ("response_type", "code id_token"),
            ("scope", "openid"), ("nonce", "n"), ("redirect_uri", Oidc.Callback));

        Assert.Equal("unsupported_response_type", Oidc.ResponseParams(resp)["error"]);
    }

    [Fact]
    public async Task DPoPBoundCode_RequiresTheSameKeyAtTheTokenEndpoint()
    {
        using var bound = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        using var other = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        await using var app = TestWebApp.Create(o =>
        {
            o.DPoPEnabled = true;
            o.PushedAuthorizationEnabled = true;
        });

        // A DPoP proof at PAR binds the code (RFC 9449 §10.1).
        var push = new HttpRequestMessage(HttpMethod.Post, "/connect/par")
        {
            Headers = { Authorization = Oidc.Basic("par-client", "par-secret") },
            Content = new FormUrlEncodedContent(
            [
                new("response_type", "code"), new("scope", "openid"), new("redirect_uri", Oidc.Callback),
            ]),
        };
        push.Headers.Add("DPoP", DPoP(bound, "/connect/par"));
        var pushed = await app.Client.SendAsync(push);
        Assert.Equal(HttpStatusCode.Created, pushed.StatusCode);
        var requestUri = JsonDocument.Parse(await pushed.Content.ReadAsStringAsync()).RootElement.GetProperty("request_uri").GetString()!;

        // A mismatching dpop_jkt next to the proof is refused.
        var mismatched = new HttpRequestMessage(HttpMethod.Post, "/connect/par")
        {
            Headers = { Authorization = Oidc.Basic("par-client", "par-secret") },
            Content = new FormUrlEncodedContent(
            [
                new("response_type", "code"), new("scope", "openid"), new("redirect_uri", Oidc.Callback),
                new("dpop_jkt", "not-the-key-thumbprint"),
            ]),
        };
        mismatched.Headers.Add("DPoP", DPoP(bound, "/connect/par"));
        await Oidc.AssertErrorAsync(await app.Client.SendAsync(mismatched), HttpStatusCode.BadRequest, "invalid_dpop_proof");

        await Oidc.SignInAsync(app, "alice");
        var code = Oidc.ResponseParams(await Oidc.AuthorizeAsync(app, ("client_id", "par-client"), ("request_uri", requestUri)))["code"]!;
        List<KeyValuePair<string, string>> form = [new("grant_type", "authorization_code"), new("code", code), new("redirect_uri", Oidc.Callback)];

        await Oidc.AssertErrorAsync(await Oidc.TokenAsync(app, form, ("par-client", "par-secret"), dpop: DPoP(other, "/connect/token")),
            HttpStatusCode.BadRequest, "invalid_grant");
    }

    [Fact]
    public async Task DeniedInteraction_ReturnsAccessDeniedToTheClient()
    {
        await using var app = TestWebApp.Create(o => o.StaticClients =
        [
            .. o.StaticClients.Where(c => c.ClientId != "test-client"),
            new Abstractions.Models.Client
            {
                ClientId = "test-client", ClientSecret = "test-secret",
                AllowedGrantTypes = ["authorization_code"], AllowedScopes = ["openid"],
                RedirectUris = [Oidc.Callback], RequirePkce = false, RequireConsent = true,
            },
        ]);
        await Oidc.SignInAsync(app, "alice");

        // Consent is required: the provider sends the End-User to the consent page.
        var toConsent = await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"),
            ("scope", "openid"), ("state", "s4"), ("redirect_uri", Oidc.Callback));
        var returnUrl = Microsoft.AspNetCore.WebUtilities.QueryHelpers
            .ParseQuery(toConsent.Headers.Location!.OriginalString.Split('?', 2)[1])["returnUrl"].ToString();

        // The End-User refuses; the host records it and follows the return URL.
        Assert.True(await app.Services.GetRequiredService<Interaction.InteractionDenialService>().DenyAsync(returnUrl));
        var resp = await app.Client.GetAsync(returnUrl);

        var response = Oidc.ResponseParams(resp);
        Assert.Equal("access_denied", response["error"]);
        Assert.Equal("s4", response["state"]);
    }

    private static string DPoP(System.Security.Cryptography.ECDsa key, string path)
    {
        var p = key.ExportParameters(false);
        return new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString(), ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["htm"] = "POST", ["htu"] = "https://auth.test.example.com" + path,
            },
            TokenType = "dpop+jwt",
            SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(key), "ES256"),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, object>
                {
                    ["kty"] = "EC", ["crv"] = "P-256",
                    ["x"] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(p.Q.X!),
                    ["y"] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(p.Q.Y!),
                },
            },
        });
    }

    // ── OIDC Registration §2 display metadata ──────────────────────────────

    [Fact]
    public async Task DynamicRegistration_KeepsPolicyAndTermsUris()
    {
        await using var app = TestWebApp.Create(o => o.DcrEnabled = true);
        var resp = await app.Client.PostAsync("/connect/register", new StringContent(JsonSerializer.Serialize(new
        {
            redirect_uris = new[] { Oidc.Callback },
            policy_uri = "https://client.test.example.com/policy",
            tos_uri = "https://client.test.example.com/tos",
        }), System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal("https://client.test.example.com/policy", body.GetProperty("policy_uri").GetString());
        Assert.Equal("https://client.test.example.com/tos", body.GetProperty("tos_uri").GetString());
        var client = await app.Services.GetRequiredService<Abstractions.Adapters.IClientStore>()
            .FindClientAsync(body.GetProperty("client_id").GetString()!);
        Assert.Equal("https://client.test.example.com/tos", client!.TosUri);
    }

    // ── Dynamic registration without PKCE (OIDC Dynamic profile) ───────────

    [Theory]
    [InlineData(true, "client_secret_basic", true)]
    [InlineData(false, "client_secret_basic", false)]
    [InlineData(false, "none", true)]   // public clients always need PKCE
    public async Task DynamicClients_PkceDefault_FollowsTheOption(bool requireByDefault, string authMethod, bool expected)
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DcrEnabled = true;
            o.DcrRequirePkceByDefault = requireByDefault;
        });
        var resp = await app.Client.PostAsync("/connect/register", new StringContent(JsonSerializer.Serialize(new
        {
            redirect_uris = new[] { Oidc.Callback },
            token_endpoint_auth_method = authMethod,
        }), System.Text.Encoding.UTF8, "application/json"));
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var client = await app.Services.GetRequiredService<Abstractions.Adapters.IClientStore>()
            .FindClientAsync(body.GetProperty("client_id").GetString()!);
        Assert.Equal(expected, client!.RequirePkce);
    }
}
