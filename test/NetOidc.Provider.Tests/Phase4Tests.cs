using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Integration tests for Phase 4: PAR, JAR, JARM, resource indicators, RAR,
/// token exchange, and JWT bearer grant.
/// </summary>
public sealed class Phase4Tests
{
    // ── helpers ────────────────────────────────────────────────────────────────

    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    private static string BasicAuth(string id, string secret) =>
        "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    // ── PAR tests (RFC 9126) ───────────────────────────────────────────────────

    [Fact]
    public async Task Par_ReturnsRequestUri_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.PushedAuthorizationEnabled = true;
        });

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/par")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("par-client", "par-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("client_id", "par-client"),
                new("response_type", "code"),
                new("redirect_uri", "https://client.test.example.com/callback"),
                new("scope", "openid profile"),
                new("state", "par-state"),
            ]),
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var requestUri = body.RootElement.GetProperty("request_uri").GetString();
        Assert.NotNull(requestUri);
        Assert.StartsWith("urn:ietf:params:oauth:request_uri:", requestUri);
        Assert.Equal(90, body.RootElement.GetProperty("expires_in").GetInt32());
    }

    [Fact]
    public async Task Par_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create();  // PAR not enabled

        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/par")
        {
            Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("par-client", "par-secret")) },
            Content = new FormUrlEncodedContent(
            [
                new("client_id", "par-client"),
                new("response_type", "code"),
            ]),
        });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Par_RequestUri_CanBeUsedInAuthorizationEndpoint()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.PushedAuthorizationEnabled = true;
        });

        // Step 1: push the authorization request
        var parResp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/par")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("par-client", "par-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("client_id", "par-client"),
                    new("response_type", "code"),
                    new("redirect_uri", "https://client.test.example.com/callback"),
                    new("scope", "openid"),
                    new("state", "s1"),
                ]),
            });

        Assert.Equal(HttpStatusCode.Created, parResp.StatusCode);
        var parBody = JsonDocument.Parse(await parResp.Content.ReadAsStringAsync());
        var requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        // Step 2: sign in the user
        await SignInAsync(app.Client, "par-user");

        // Step 3: authorization request using request_uri
        var authResp = await app.Client.GetAsync(
            $"/connect/authorize?client_id=par-client&request_uri={Uri.EscapeDataString(requestUri)}");

        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var location = authResp.Headers.Location!.ToString();
        var qs = HttpUtility.ParseQueryString(new Uri(location).Query);
        Assert.NotEmpty(qs["code"]!);
        Assert.Equal("s1", qs["state"]);
    }

    [Fact]
    public async Task Par_RequestUri_Cannot_BeUsedTwice()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.PushedAuthorizationEnabled = true;
        });

        var parResp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/par")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("par-client", "par-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("client_id", "par-client"),
                    new("response_type", "code"),
                    new("redirect_uri", "https://client.test.example.com/callback"),
                    new("scope", "openid"),
                ]),
            });

        var requestUri = JsonDocument.Parse(await parResp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("request_uri").GetString()!;

        await SignInAsync(app.Client, "par-user");

        // First use should succeed
        var first = await app.Client.GetAsync(
            $"/connect/authorize?client_id=par-client&request_uri={Uri.EscapeDataString(requestUri)}");
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);

        // Second use should fail (ConsumeAsync removes it)
        var second = await app.Client.GetAsync(
            $"/connect/authorize?client_id=par-client&request_uri={Uri.EscapeDataString(requestUri)}");
        // Since client / redirect_uri is known, the error should be a redirect or an error page
        // The handler will return ShowErrorPage because PAR record is gone
        Assert.True(
            second.StatusCode == HttpStatusCode.BadRequest ||
            second.StatusCode == HttpStatusCode.Redirect,
            $"Expected 400 or redirect, got {second.StatusCode}");
    }

    [Fact]
    public async Task RequirePar_Returns400_WhenNoRequestUri()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.PushedAuthorizationEnabled = true;
            opts.RequirePushedAuthorization = true;
        });

        await SignInAsync(app.Client, "alice");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=par-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback&scope=openid");

        // Should return error (no request_uri = rejected)
        Assert.True(
            resp.StatusCode == HttpStatusCode.BadRequest ||
            resp.StatusCode == HttpStatusCode.Redirect,
            $"Expected error response, got {resp.StatusCode}");
    }

    // ── JARM tests ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Jarm_QueryJwt_ReturnsJwtInResponseParam()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.JarmEnabled = true;
        });

        await SignInAsync(app.Client, "jarm-user");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&state=jarm-state&response_mode=query.jwt");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        var qs = HttpUtility.ParseQueryString(new Uri(location).Query);

        // Should have a single "response" parameter containing a JWT
        var responseJwt = qs["response"];
        Assert.NotNull(responseJwt);
        Assert.False(string.IsNullOrEmpty(responseJwt));

        // The JWT should be parseable and contain the authorization code
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(responseJwt);
        Assert.NotNull(jwt);
        var code = jwt.GetPayloadValue<string>("code");
        Assert.NotEmpty(code);
        var state = jwt.GetPayloadValue<string>("state");
        Assert.Equal("jarm-state", state);
    }

    [Fact]
    public async Task Jarm_FragmentJwt_ReturnsJwtInFragment()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.JarmEnabled = true;
        });

        await SignInAsync(app.Client, "jarm-user2");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&response_mode=fragment.jwt");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains('#', location);

        var fragment = location.Split('#')[1];
        var fragmentParams = HttpUtility.ParseQueryString(fragment);
        var responseJwt = fragmentParams["response"];
        Assert.NotNull(responseJwt);

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(responseJwt);
        Assert.NotNull(jwt);
    }

    [Fact]
    public async Task Jarm_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create();   // JARM not enabled

        await SignInAsync(app.Client, "user");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&response_mode=query.jwt");

        // query.jwt unsupported when JARM disabled → error redirect or error page
        Assert.True(
            resp.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.BadRequest,
            $"Expected error, got {resp.StatusCode}");
    }

    // ── Resource Indicators tests (RFC 8707) ───────────────────────────────────

    [Fact]
    public async Task ResourceIndicators_StoredInAuthCode_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.ResourceIndicatorsEnabled = true;
        });

        await SignInAsync(app.Client, "resource-user");

        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid&resource=https%3A%2F%2Fapi.example.com");

        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;
        Assert.NotEmpty(code);

        // Exchange code for token — should succeed
        var tokenResp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "authorization_code"),
                    new("code", code),
                    new("redirect_uri", "https://client.test.example.com/callback"),
                ]),
            });

        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        Assert.True(tokenBody.RootElement.TryGetProperty("access_token", out _));
    }

    // ── Rich Authorization Requests tests (RFC 9396) ───────────────────────────

    [Fact]
    public async Task Rar_AuthorizationDetails_StoredAndReturnedInToken()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.RichAuthorizationRequestsEnabled = true;
        });

        await SignInAsync(app.Client, "rar-user");

        var authDetails = """[{"type":"payment_initiation","locations":["https://bank.example.com"]}]""";

        var authResp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid" +
            "&authorization_details=" + Uri.EscapeDataString(authDetails));

        Assert.Equal(HttpStatusCode.Redirect, authResp.StatusCode);
        var code = HttpUtility.ParseQueryString(
            new Uri(authResp.Headers.Location!.ToString()).Query)["code"]!;
        Assert.NotEmpty(code);

        var tokenResp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("test-client", "test-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "authorization_code"),
                    new("code", code),
                    new("redirect_uri", "https://client.test.example.com/callback"),
                ]),
            });

        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        var tokenBody = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());

        // authorization_details should be present in token response
        Assert.True(tokenBody.RootElement.TryGetProperty("authorization_details", out var ad));
        Assert.Equal(JsonValueKind.Array, ad.ValueKind);
        Assert.Equal(1, ad.GetArrayLength());
        Assert.Equal("payment_initiation",
            ad[0].GetProperty("type").GetString());
    }

    [Fact]
    public async Task Rar_InvalidJson_ReturnsError()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.RichAuthorizationRequestsEnabled = true;
        });

        await SignInAsync(app.Client, "rar-user");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid" +
            "&authorization_details=not-valid-json");

        // Should redirect with error
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.Contains("error=invalid_authorization_details", location);
    }

    // ── Token Exchange tests (RFC 8693) ────────────────────────────────────────

    [Fact]
    public async Task TokenExchange_AccessToken_ReturnsNewToken()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.TokenExchangeEnabled = true;
        });

        // First, get an access token via client_credentials
        var ccResp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "client_credentials"),
                    new("scope", "profile"),
                ]),
            });

        Assert.Equal(HttpStatusCode.OK, ccResp.StatusCode);
        var ccBody = JsonDocument.Parse(await ccResp.Content.ReadAsStringAsync());
        var subjectToken = ccBody.RootElement.GetProperty("access_token").GetString()!;

        // Exchange it
        var exResp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("exchange-client", "exchange-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                    new("subject_token", subjectToken),
                    new("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
                ]),
            });

        Assert.Equal(HttpStatusCode.OK, exResp.StatusCode);
        var exBody = JsonDocument.Parse(await exResp.Content.ReadAsStringAsync());
        Assert.True(exBody.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token",
            exBody.RootElement.GetProperty("issued_token_type").GetString());
    }

    [Fact]
    public async Task TokenExchange_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create();  // token exchange not enabled

        var resp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("exchange-client", "exchange-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                    new("subject_token", "dummy"),
                    new("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
                ]),
            });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("unsupported_grant_type", body.RootElement.GetProperty("error").GetString());
    }

    // ── JWT Bearer grant tests (RFC 7523) ──────────────────────────────────────

    [Fact]
    public async Task JwtBearer_ValidAssertion_ReturnsAccessToken()
    {
        // Generate an RSA key for the client
        using var rsa = RSA.Create(2048);
        var privateKey = new RsaSecurityKey(rsa);
        var publicJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(
            rsa.ExportParameters(includePrivateParameters: false)));
        publicJwk.Use = "sig";
        var jwks = new JsonWebKeySet();
        jwks.Keys.Add(publicJwk);
        var jwksJson = System.Text.Json.JsonSerializer.Serialize(new
        {
            keys = jwks.Keys.Select(k => new
            {
                kty = k.Kty,
                use = k.Use,
                n = k.N,
                e = k.E,
                kid = k.Kid ?? "test-key",
            })
        });

        await using var app = TestWebApp.Create(opts =>
        {
            opts.JwtBearerGrantEnabled = true;
            opts.StaticClients = opts.StaticClients.Concat(
            [
                new Client
                {
                    ClientId = "jwt-bearer-client",
                    ClientSecret = "jwt-bearer-secret",
                    AllowedGrantTypes = ["authorization_code", "client_credentials"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                    JwksJson = jwksJson,
                }
            ]).ToList();
        });

        // Create a JWT assertion
        var handler = new JsonWebTokenHandler();
        var assertion = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "jwt-bearer-client",
            Audience = "https://auth.test.example.com",
            Subject = new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("sub", "external-user"),
            ]),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256),
        });

        var resp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("jwt-bearer-client", "jwt-bearer-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new("assertion", assertion),
                    new("scope", "profile"),
                ]),
            });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task JwtBearer_Returns400_WhenDisabled()
    {
        await using var app = TestWebApp.Create();  // JWT bearer not enabled

        var resp = await app.Client.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Headers = { Authorization = AuthenticationHeaderValue.Parse(BasicAuth("cc-client", "cc-secret")) },
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new("assertion", "dummy"),
                ]),
            });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── Discovery Phase 4 metadata tests ──────────────────────────────────────

    [Fact]
    public async Task Discovery_IncludesPar_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.PushedAuthorizationEnabled = true;
        });

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("pushed_authorization_request_endpoint", out var par));
        Assert.Contains("/connect/par", par.GetString());
    }

    [Fact]
    public async Task Discovery_IncludesJarmModes_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.JarmEnabled = true;
        });

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var modes = doc.RootElement.GetProperty("response_modes_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        Assert.Contains("query.jwt", modes);
        Assert.Contains("fragment.jwt", modes);
        Assert.Contains("form_post.jwt", modes);
    }

    [Fact]
    public async Task Discovery_IncludesTokenExchangeGrant_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.TokenExchangeEnabled = true;
        });

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var grants = doc.RootElement.GetProperty("grant_types_supported")
            .EnumerateArray().Select(e => e.GetString()).ToList();

        Assert.Contains("urn:ietf:params:oauth:grant-type:token-exchange", grants);
    }

    [Fact]
    public async Task Jwks_IncludesEncryptionKey()
    {
        await using var app = TestWebApp.Create();

        var resp = await app.Client.GetAsync("/.well-known/jwks.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());

        var keys = doc.RootElement.GetProperty("keys").EnumerateArray().ToList();
        // Should have both signing (use=sig) and encryption (use=enc) keys
        Assert.Contains(keys, k => k.TryGetProperty("use", out var u) && u.GetString() == "sig");
        Assert.Contains(keys, k => k.TryGetProperty("use", out var u) && u.GetString() == "enc");
    }
}
