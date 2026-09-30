using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Vci;

namespace NetOidc.Provider.Tests;

/// <summary>
/// REMEDIATION_PLAN P6.1: negative security tests applied uniformly to every endpoint —
/// missing or wrong client credentials, forged bearer tokens, malformed input, duplicate
/// parameters, wrong methods and response hygiene. Losers must fail with the documented
/// error, never with a server error or leaked internals.
/// </summary>
public sealed class EndpointNegativeTests : IAsyncLifetime
{
    private TestWebApp _app = null!;

    public Task InitializeAsync()
    {
        _app = TestWebApp.Create(o =>
        {
            o.PushedAuthorizationEnabled = true;
            o.DeviceFlowEnabled = true;
            o.CibaEnabled = true;
            o.DcrEnabled = true;
            o.LogoutEnabled = true;
            o.DPoPEnabled = true;
            o.VciEnabled = true;
            o.VciCredentialConfigurations.Add(new CredentialConfiguration { Id = "Badge", Format = "jwt_vc_json", Scope = "profile" });
            o.RetrieveDeferredCredential = (_, _) => Task.FromResult<CredentialIssuanceResult>("deferred");
            o.OnCredentialNotification = (_, _) => Task.CompletedTask;
            o.UnauthenticatedRequestsPerMinute = 0;
        });
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _app.DisposeAsync();

    /// <summary>Endpoints that require client authentication, with a minimal valid-looking body.</summary>
    public static TheoryData<string, string> ClientAuthenticatedEndpoints => new()
    {
        { "/connect/token", "grant_type=client_credentials&scope=profile" },
        { "/connect/introspect", "token=abc" },
        { "/connect/revoke", "token=abc" },
        { "/connect/par", "response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" },
        { "/connect/device_authorization", "scope=openid" },
        { "/connect/ciba", "scope=openid&login_hint=alice" },
    };

    /// <summary>Endpoints that require an access token.</summary>
    public static TheoryData<string, string> BearerProtectedEndpoints => new()
    {
        { "/connect/userinfo", "" },
        { "/connect/credential", """{"credential_configuration_id":"Badge"}""" },
        { "/connect/deferred_credential", """{"transaction_id":"abc"}""" },
        { "/connect/notification", """{"notification_id":"abc","event":"credential_accepted"}""" },
    };

    /// <summary>Every endpoint that accepts a POST.</summary>
    public static TheoryData<string> PostEndpoints => new()
    {
        "/connect/authorize", "/connect/token", "/connect/userinfo", "/connect/introspect", "/connect/revoke",
        "/connect/end_session", "/connect/register", "/connect/par", "/connect/device_authorization",
        "/connect/device", "/connect/ciba", "/connect/nonce", "/connect/credential",
        "/connect/deferred_credential", "/connect/notification",
    };

    // ── Client authentication ───────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(ClientAuthenticatedEndpoints))]
    public async Task MissingClientCredentials_AreRejected(string path, string body)
    {
        var resp = await PostFormAsync(path, body, "client_id=cc-client");
        await AssertInvalidClientAsync(resp);
    }

    [Theory]
    [MemberData(nameof(ClientAuthenticatedEndpoints))]
    public async Task WrongClientSecret_IsRejected(string path, string body)
    {
        var resp = await PostFormAsync(path, body, auth: Oidc.Basic(ClientFor(path), "wrong-secret"));
        await AssertInvalidClientAsync(resp);
    }

    [Theory]
    [MemberData(nameof(ClientAuthenticatedEndpoints))]
    public async Task UnknownClient_IsRejected(string path, string body)
    {
        var resp = await PostFormAsync(path, body, auth: Oidc.Basic("no-such-client", "secret"));
        await AssertInvalidClientAsync(resp);
    }

    [Theory]
    [MemberData(nameof(ClientAuthenticatedEndpoints))]
    public async Task TwoAuthenticationMethods_AreRejected(string path, string body)
    {
        // RFC 6749 §2.3: a client MUST NOT use more than one authentication method per request.
        var id = ClientFor(path);
        var resp = await PostFormAsync(path, body, $"client_id={id}&client_secret={SecretFor(id)}", Oidc.Basic(id, SecretFor(id)));
        Assert.True(resp.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized, await DescribeAsync(resp));
        AssertNoLeak(await resp.Content.ReadAsStringAsync());
    }

    // ── Bearer tokens ───────────────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(BearerProtectedEndpoints))]
    public async Task MissingAccessToken_IsRejectedWithChallenge(string path, string body)
    {
        var resp = await PostBearerAsync(path, body, null);
        AssertBearerChallenge(resp);
    }

    [Theory]
    [MemberData(nameof(BearerProtectedEndpoints))]
    public async Task GarbageAccessToken_IsRejected(string path, string body)
    {
        var resp = await PostBearerAsync(path, body, "not-a-token");
        AssertBearerChallenge(resp);
    }

    [Theory]
    [MemberData(nameof(BearerProtectedEndpoints))]
    public async Task UnsignedAccessToken_IsRejected(string path, string body)
    {
        var real = new JsonWebToken(await _app.IssueUserAccessTokenAsync("alice", "test-client", "openid", "profile"));
        // Same claims, "alg":"none", no signature.
        var header = Base64UrlEncoder.Encode("""{"alg":"none","typ":"at+jwt"}""");
        var forged = $"{header}.{real.EncodedPayload}.";

        AssertBearerChallenge(await PostBearerAsync(path, body, forged));
    }

    [Theory]
    [MemberData(nameof(BearerProtectedEndpoints))]
    public async Task AccessTokenSignedWithForeignKey_IsRejected(string path, string body)
    {
        var real = new JsonWebToken(await _app.IssueUserAccessTokenAsync("alice", "test-client", "openid", "profile"));
        using var rsa = RSA.Create(2048);
        var forged = new JsonWebTokenHandler().CreateToken(
            Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(real.EncodedPayload)),
            new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = real.Kid }, SecurityAlgorithms.RsaSha256),
            new Dictionary<string, object> { ["typ"] = "at+jwt" });

        AssertBearerChallenge(await PostBearerAsync(path, body, forged));
    }

    [Theory]
    [MemberData(nameof(BearerProtectedEndpoints))]
    public async Task TamperedAccessTokenPayload_IsRejected(string path, string body)
    {
        var real = new JsonWebToken(await _app.IssueUserAccessTokenAsync("alice", "test-client", "openid", "profile"));
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(real.EncodedPayload)).Replace("\"alice\"", "\"mallory\"");
        var forged = $"{real.EncodedHeader}.{Base64UrlEncoder.Encode(payload)}.{real.EncodedSignature}";

        AssertBearerChallenge(await PostBearerAsync(path, body, forged));
    }

    [Fact]
    public async Task AccessTokenInQueryString_IsNotAccepted()
    {
        var token = await _app.IssueUserAccessTokenAsync("alice", "test-client", "openid");
        var resp = await _app.Client.GetAsync($"/connect/userinfo?access_token={token}");
        AssertBearerChallenge(resp);
    }

    // ── Malformed input ─────────────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(PostEndpoints))]
    public async Task MalformedBodies_NeverCauseServerErrors(string path)
    {
        string[] bodies =
        [
            "",
            "=&=&&==",
            "%%%%%zz",
            "{\"not\":\"a form\"}",
            "client_id=" + new string('a', 20_000),
            "grant_type=authorization_code&code=%00%01%02&redirect_uri=javascript:alert(1)",
            "request=eyJhbGciOiJub25lIn0.e30.&client_id=test-client",
            "token=" + Uri.EscapeDataString("eyJhbGciOiJIUzI1NiJ9." + new string('A', 5000) + ".x"),
        ];
        foreach (var body in bodies)
        {
            foreach (var mediaType in new[] { "application/x-www-form-urlencoded", "application/json", "text/plain" })
            {
                var req = new HttpRequestMessage(HttpMethod.Post, path)
                {
                    Content = new StringContent(body, Encoding.UTF8, mediaType),
                };
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "x.y.z");
                var resp = await _app.Client.SendAsync(req);
                var text = await resp.Content.ReadAsStringAsync();
                Assert.True((int)resp.StatusCode < 500, $"{path} [{mediaType}] {body[..Math.Min(40, body.Length)]}: {(int)resp.StatusCode} {text}");
                AssertNoLeak(text);
            }
        }
    }

    [Fact]
    public async Task MalformedRequestObjects_AreRejectedWithoutServerErrors()
    {
        using var rsa = RSA.Create(2048);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(false)));
        var jwks = JsonSerializer.Serialize(new { keys = new[] { new { kty = jwk.Kty, n = jwk.N, e = jwk.E } } });
        await using var app = TestWebApp.Create(o =>
        {
            o.JarEnabled = true;
            o.PushedAuthorizationEnabled = true;
            o.CibaEnabled = true;
            o.StaticClients =
            [
                .. o.StaticClients,
                new Abstractions.Models.Client
                {
                    ClientId = "jar-rp",
                    ClientSecret = "jar-rp-secret",
                    AllowedGrantTypes = ["authorization_code", "urn:openid:params:grant-type:ciba"],
                    AllowedScopes = ["openid"],
                    RedirectUris = [Oidc.Callback],
                    CibaDeliveryMode = "poll",
                    JwksJson = jwks,
                },
            ];
        });
        await Oidc.SignInAsync(app, "alice");

        string[] requests = ["a.b.c", "....", "a.b.c.d.e", "eyJ.eyJ.", "e30.e30.", "e30.e30.e30.e30.e30", "%7B.%7D.x"];
        foreach (var request in requests)
        {
            var responses = new[]
            {
                await app.Client.GetAsync($"/connect/authorize?client_id=jar-rp&request={request}"),
                await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/par")
                {
                    Headers = { Authorization = Oidc.Basic("jar-rp", "jar-rp-secret") },
                    Content = new FormUrlEncodedContent([new("request", request)]),
                }),
                await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
                {
                    Headers = { Authorization = Oidc.Basic("jar-rp", "jar-rp-secret") },
                    Content = new FormUrlEncodedContent([new("request", request)]),
                }),
            };
            foreach (var resp in responses)
                Assert.True((int)resp.StatusCode < 500, $"{request} at {resp.RequestMessage!.RequestUri!.AbsolutePath}: {await DescribeAsync(resp)}");
        }
    }

    [Theory]
    [InlineData("grant_type=client_credentials&grant_type=client_credentials&scope=profile")]
    [InlineData("grant_type=client_credentials&scope=profile&scope=openid")]
    public async Task DuplicateParameters_AreRejectedAtTokenEndpoint(string body)
    {
        // RFC 6749 §3.1/§3.2: request and response parameters MUST NOT be included more than once.
        var resp = await PostFormAsync("/connect/token", body, auth: Oidc.Basic("cc-client", "cc-secret"));
        await Oidc.AssertErrorAsync(resp, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task DuplicateParameters_AreRejectedAtAuthorizationEndpoint()
    {
        await Oidc.SignInAsync(_app, "alice");
        var resp = await _app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code&scope=openid&redirect_uri=" +
            Uri.EscapeDataString(Oidc.Callback) + "&redirect_uri=" + Uri.EscapeDataString("https://evil.example.com/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Null(resp.Headers.Location);
    }

    [Theory]
    [InlineData("GET", "/connect/token")]
    [InlineData("GET", "/connect/introspect")]
    [InlineData("GET", "/connect/revoke")]
    [InlineData("GET", "/connect/par")]
    [InlineData("GET", "/connect/ciba")]
    [InlineData("GET", "/connect/credential")]
    [InlineData("PUT", "/connect/authorize")]
    [InlineData("DELETE", "/connect/userinfo")]
    public async Task WrongHttpMethod_IsNotRouted(string method, string path)
    {
        var resp = await _app.Client.SendAsync(new HttpRequestMessage(new HttpMethod(method), path));
        Assert.True(resp.StatusCode is HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotFound, $"{(int)resp.StatusCode}");
    }

    // ── Response hygiene ────────────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(ClientAuthenticatedEndpoints))]
    public async Task ErrorResponses_AreJsonAndNotCached(string path, string body)
    {
        var resp = await PostFormAsync(path, body, auth: Oidc.Basic(ClientFor(path), "wrong-secret"));
        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
        Assert.True(resp.Headers.CacheControl?.NoStore == true, $"{path}: Cache-Control {resp.Headers.CacheControl}");
    }

    [Fact]
    public async Task TokenResponses_AreNotCached()
    {
        var resp = await PostFormAsync("/connect/token", "grant_type=client_credentials&scope=profile",
            auth: Oidc.Basic("cc-client", "cc-secret"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.CacheControl?.NoStore == true);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string ClientFor(string path) => path switch
    {
        "/connect/par" => "par-client",
        "/connect/device_authorization" => "device-client",
        "/connect/ciba" => "ciba-client",
        _ => "cc-client",
    };

    private static string SecretFor(string clientId) => clientId.Replace("-client", "-secret");

    private Task<HttpResponseMessage> PostFormAsync(
        string path, string body, string? extra = null, AuthenticationHeaderValue? auth = null)
    {
        var content = string.IsNullOrEmpty(extra) ? body : $"{body}&{extra}";
        var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(content, Encoding.UTF8, "application/x-www-form-urlencoded"),
        };
        req.Headers.Authorization = auth;
        return _app.Client.SendAsync(req);
    }

    private Task<HttpResponseMessage> PostBearerAsync(string path, string body, string? token)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = path == "/connect/userinfo"
                ? new FormUrlEncodedContent([])
                : new StringContent(body, Encoding.UTF8, "application/json"),
        };
        if (token is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return _app.Client.SendAsync(req);
    }

    private static async Task AssertInvalidClientAsync(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.Unauthorized, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal("invalid_client", JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
        AssertNoLeak(body);
    }

    private static void AssertBearerChallenge(HttpResponseMessage resp)
    {
        Assert.True(resp.StatusCode == HttpStatusCode.Unauthorized, $"{(int)resp.StatusCode}");
        Assert.NotEmpty(resp.Headers.WwwAuthenticate);
    }

    private static void AssertNoLeak(string body)
    {
        Assert.DoesNotContain("Exception", body);
        Assert.DoesNotContain("   at ", body);
        Assert.DoesNotContain("IDX", body); // Microsoft.IdentityModel diagnostic codes
    }

    private static async Task<string> DescribeAsync(HttpResponseMessage resp) =>
        $"{(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}";
}
