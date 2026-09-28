using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Regression tests for REMEDIATION_PLAN P1.2 (token exchange) and P1.3 (jwt-bearer grant).
/// </summary>
public sealed class GrantSecurityTests
{
    private const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string JwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
    private const string IdTokenType = "urn:ietf:params:oauth:token-type:id_token";

    // ── P1.2 Token exchange ─────────────────────────────────────────────────

    [Fact]
    public async Task TokenExchange_DefaultPolicy_RejectsTokenIssuedToAnotherClient()
    {
        await using var app = TestWebApp.Create(o => o.TokenExchangeEnabled = true);
        var foreignToken = await ClientCredentialsAsync(app, "cc-client", "cc-secret", "profile");

        var resp = await ExchangeAsync(app, foreignToken, AccessTokenType);

        await AssertErrorAsync(resp, "invalid_grant");
    }

    [Fact]
    public async Task TokenExchange_AllowsOwnToken_ByDefault()
    {
        await using var app = TestWebApp.Create(o => o.TokenExchangeEnabled = true);
        var ownToken = await ClientCredentialsAsync(app, "exchange-client", "exchange-secret", "profile");

        var resp = await ExchangeAsync(app, ownToken, AccessTokenType);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task TokenExchange_RejectsScopeEscalation()
    {
        await using var app = TestWebApp.Create(o => o.TokenExchangeEnabled = true);
        var ownToken = await ClientCredentialsAsync(app, "exchange-client", "exchange-secret", "profile");

        var resp = await ExchangeAsync(app, ownToken, AccessTokenType, scope: "openid profile");

        await AssertErrorAsync(resp, "invalid_scope");
    }

    [Fact]
    public async Task TokenExchange_NewTokenCannotExceedClientScopes_EvenIfPolicyAllows()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.TokenExchangeEnabled = true;
            o.AuthorizeTokenExchange = (_, _) => Task.FromResult(true);
            o.StaticClients =
            [
                .. o.StaticClients,
                new Client
                {
                    ClientId = "narrow-exchanger",
                    ClientSecret = "narrow-secret",
                    AllowedGrantTypes = [TokenExchange],
                    AllowedScopes = ["openid"],
                },
            ];
        });
        var token = await ClientCredentialsAsync(app, "cc-client", "cc-secret", "profile");

        var resp = await ExchangeAsync(app, token, AccessTokenType,
            clientId: "narrow-exchanger", secret: "narrow-secret", scope: "profile");

        await AssertErrorAsync(resp, "invalid_scope");
    }

    [Fact]
    public async Task TokenExchange_RejectsRevokedAccessToken()
    {
        await using var app = TestWebApp.Create(o => o.TokenExchangeEnabled = true);
        var ownToken = await ClientCredentialsAsync(app, "exchange-client", "exchange-secret", "profile");

        var revoke = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/revoke")
        {
            Headers = { Authorization = Basic("exchange-client", "exchange-secret") },
            Content = new FormUrlEncodedContent([new("token", ownToken)]),
        });
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        var resp = await ExchangeAsync(app, ownToken, AccessTokenType);

        await AssertErrorAsync(resp, "invalid_grant");
    }

    [Fact]
    public async Task TokenExchange_RejectsExpiredIdToken()
    {
        await using var app = TestWebApp.Create(o => o.TokenExchangeEnabled = true);
        var keys = app.Services.GetRequiredService<SigningKeyProvider>();
        var expired = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://auth.test.example.com",
            Audience = "exchange-client",
            Subject = new ClaimsIdentity([new Claim("sub", "alice")]),
            NotBefore = DateTime.UtcNow.AddHours(-2),
            IssuedAt = DateTime.UtcNow.AddHours(-2),
            Expires = DateTime.UtcNow.AddHours(-1),
            SigningCredentials = keys.GetSigningCredentials(),
        });

        var resp = await ExchangeAsync(app, expired, IdTokenType);

        await AssertErrorAsync(resp, "invalid_grant");
    }

    [Fact]
    public async Task TokenExchange_RejectsClientWithoutGrantType()
    {
        await using var app = TestWebApp.Create(o => o.TokenExchangeEnabled = true);
        var token = await ClientCredentialsAsync(app, "cc-client", "cc-secret", "profile");

        var resp = await ExchangeAsync(app, token, AccessTokenType, clientId: "cc-client", secret: "cc-secret");

        await AssertErrorAsync(resp, "unauthorized_client");
    }

    [Fact]
    public async Task TokenExchange_RejectsActorToken()
    {
        await using var app = TestWebApp.Create(o => o.TokenExchangeEnabled = true);
        var token = await ClientCredentialsAsync(app, "exchange-client", "exchange-secret", "profile");

        var resp = await ExchangeAsync(app, token, AccessTokenType, actorToken: token);

        await AssertErrorAsync(resp, "invalid_request");
    }

    // ── P1.3 JWT bearer ─────────────────────────────────────────────────────

    [Fact]
    public async Task JwtBearer_IsDeniedWithoutSubjectPolicy()
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateJwtBearerApp(rsa, policy: null);

        var resp = await JwtBearerAsync(app, CreateAssertion(rsa, "victim-user", jti: "j1"));

        await AssertErrorAsync(resp, "invalid_grant");
    }

    [Fact]
    public async Task JwtBearer_RejectsReplayedAssertion()
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateJwtBearerApp(rsa, policy: (_, _) => Task.FromResult(true));
        var assertion = CreateAssertion(rsa, "external-user", jti: "once");

        Assert.Equal(HttpStatusCode.OK, (await JwtBearerAsync(app, assertion)).StatusCode);
        await AssertErrorAsync(await JwtBearerAsync(app, assertion), "invalid_grant");
    }

    [Fact]
    public async Task JwtBearer_RejectsAssertionWithoutJti()
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateJwtBearerApp(rsa, policy: (_, _) => Task.FromResult(true));

        var resp = await JwtBearerAsync(app, CreateAssertion(rsa, "external-user", jti: null));

        await AssertErrorAsync(resp, "invalid_grant");
    }

    [Fact]
    public async Task JwtBearer_RejectsScopeOutsideClientAllowance()
    {
        using var rsa = RSA.Create(2048);
        await using var app = CreateJwtBearerApp(rsa, policy: (_, _) => Task.FromResult(true));

        var resp = await JwtBearerAsync(app, CreateAssertion(rsa, "external-user", jti: "j2"), scope: "openid");

        await AssertErrorAsync(resp, "invalid_scope");
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static TestWebApp CreateJwtBearerApp(
        RSA rsa, Func<Configuration.JwtBearerContext, CancellationToken, Task<bool>>? policy)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = "k1" });
        var jwksJson = JsonSerializer.Serialize(new
        {
            keys = new[] { new { kty = jwk.Kty, use = "sig", kid = "k1", n = jwk.N, e = jwk.E } },
        });

        return TestWebApp.Create(o =>
        {
            o.JwtBearerGrantEnabled = true;
            o.AuthorizeJwtBearerSubject = policy;
            o.StaticClients =
            [
                .. o.StaticClients,
                new Client
                {
                    ClientId = "bearer-client",
                    ClientSecret = "bearer-secret",
                    AllowedGrantTypes = [JwtBearer],
                    AllowedScopes = ["profile"],
                    JwksJson = jwksJson,
                },
            ];
        });
    }

    private static string CreateAssertion(RSA rsa, string sub, string? jti)
    {
        var claims = new List<Claim> { new("sub", sub) };
        if (jti is not null) claims.Add(new Claim("jti", jti));
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "bearer-client",
            Audience = "https://auth.test.example.com",
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256),
        });
    }

    private static Task<HttpResponseMessage> JwtBearerAsync(TestWebApp app, string assertion, string scope = "profile") =>
        app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic("bearer-client", "bearer-secret") },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", JwtBearer),
                new("assertion", assertion),
                new("scope", scope),
            ]),
        });

    private static async Task<string> ClientCredentialsAsync(
        TestWebApp app, string clientId, string secret, string scope)
    {
        var resp = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic(clientId, secret) },
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "client_credentials"),
                new("scope", scope),
            ]),
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("access_token").GetString()!;
    }

    private static Task<HttpResponseMessage> ExchangeAsync(
        TestWebApp app, string subjectToken, string subjectTokenType,
        string clientId = "exchange-client", string secret = "exchange-secret",
        string? scope = null, string? actorToken = null)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", TokenExchange),
            new("subject_token", subjectToken),
            new("subject_token_type", subjectTokenType),
        };
        if (scope is not null) form.Add(new("scope", scope));
        if (actorToken is not null)
        {
            form.Add(new("actor_token", actorToken));
            form.Add(new("actor_token_type", AccessTokenType));
        }

        return app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Headers = { Authorization = Basic(clientId, secret) },
            Content = new FormUrlEncodedContent(form),
        });
    }

    private static AuthenticationHeaderValue Basic(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    private static async Task AssertErrorAsync(HttpResponseMessage resp, string error)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.BadRequest, $"{(int)resp.StatusCode}: {body}");
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(error, doc.RootElement.GetProperty("error").GetString());
    }
}
