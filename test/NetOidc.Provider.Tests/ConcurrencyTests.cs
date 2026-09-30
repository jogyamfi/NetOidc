using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Ciba;
using NetOidc.Provider.Vci;

namespace NetOidc.Provider.Tests;

/// <summary>
/// REMEDIATION_PLAN P6.1 / P1.4: every single-use artifact is redeemed exactly once when many
/// requests race for it over HTTP (not just at the adapter level).
/// </summary>
public sealed class ConcurrencyTests
{
    private const int Racers = 50;
    private const string Issuer = "https://auth.test.example.com";

    /// <summary>Releases <see cref="Racers"/> requests at once and returns their status codes.</summary>
    private static async Task<HttpStatusCode[]> RaceAsync(Func<Task<HttpResponseMessage>> send)
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = Enumerable.Range(0, Racers).Select(async _ =>
        {
            await gate.Task;
            using var resp = await send();
            return resp.StatusCode;
        }).ToArray();
        gate.SetResult();
        return await Task.WhenAll(tasks);
    }

    private static void AssertExactlyOneWinner(HttpStatusCode[] results, HttpStatusCode success = HttpStatusCode.OK)
    {
        Assert.Equal(1, results.Count(s => s == success));
        // Losers must fail cleanly, never with a server error.
        Assert.All(results.Where(s => s != success), s => Assert.Equal(HttpStatusCode.BadRequest, s));
    }

    [Fact]
    public async Task AuthorizationCode_IsRedeemedOnce()
    {
        await using var app = TestWebApp.Create();
        await Oidc.SignInAsync(app, "alice");
        var authz = await Oidc.AuthorizeAsync(app,
            ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"), ("redirect_uri", Oidc.Callback));
        var code = Oidc.ResponseParams(authz)["code"]!;

        var results = await RaceAsync(() => Oidc.TokenAsync(app,
            [new("grant_type", "authorization_code"), new("code", code), new("redirect_uri", Oidc.Callback)],
            ("test-client", "test-secret")));

        AssertExactlyOneWinner(results);
    }

    [Fact]
    public async Task RotatingRefreshToken_IsRedeemedOnce()
    {
        await using var app = TestWebApp.Create();
        var tokens = await Oidc.CodeFlowAsync(app, scope: "openid profile");
        var refresh = tokens.GetProperty("refresh_token").GetString()!;

        var results = await RaceAsync(() => Oidc.TokenAsync(app,
            [new("grant_type", "refresh_token"), new("refresh_token", refresh)],
            ("test-client", "test-secret")));

        AssertExactlyOneWinner(results);
    }

    [Fact]
    public async Task PushedRequestUri_IsUsedOnce()
    {
        await using var app = TestWebApp.Create(o => o.PushedAuthorizationEnabled = true);
        var push = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/par")
        {
            Headers = { Authorization = Oidc.Basic("par-client", "par-secret") },
            Content = new FormUrlEncodedContent(
            [
                new("response_type", "code"), new("scope", "openid"), new("redirect_uri", Oidc.Callback),
            ]),
        });
        Assert.Equal(HttpStatusCode.Created, push.StatusCode);
        var requestUri = JsonDocument.Parse(await push.Content.ReadAsStringAsync())
            .RootElement.GetProperty("request_uri").GetString()!;
        await Oidc.SignInAsync(app, "alice");

        var codes = 0;
        await RaceAsync(async () =>
        {
            var resp = await Oidc.AuthorizeAsync(app, ("client_id", "par-client"), ("request_uri", requestUri));
            if (resp.Headers.Location is not null && Oidc.ResponseParams(resp)["code"] is not null)
                Interlocked.Increment(ref codes);
            return resp;
        });

        Assert.Equal(1, codes);
    }

    [Fact]
    public async Task ApprovedDeviceCode_IsRedeemedOnce()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.DeviceFlowEnabled = true;
            o.DevicePollingIntervalSeconds = 0;
        });
        var start = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = Oidc.Basic("device-client", "device-secret") },
            Content = new FormUrlEncodedContent([new("scope", "openid")]),
        });
        var body = JsonDocument.Parse(await start.Content.ReadAsStringAsync()).RootElement;
        await Oidc.SignInAsync(app, "alice");
        var decision = await Phase6Tests.DeviceDecisionAsync(app.Client, body.GetProperty("user_code").GetString()!, "approve");
        Assert.True(decision.IsSuccessStatusCode);
        var deviceCode = body.GetProperty("device_code").GetString()!;

        var results = await RaceAsync(() => Oidc.TokenAsync(app,
            [new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), new("device_code", deviceCode)],
            ("device-client", "device-secret")));

        AssertExactlyOneWinner(results);
    }

    [Fact]
    public async Task CompletedCibaRequest_IsRedeemedOnce()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.CibaEnabled = true;
            o.CibaPollingIntervalSeconds = 0;
        });
        var start = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/ciba")
        {
            Headers = { Authorization = Oidc.Basic("ciba-client", "ciba-secret") },
            Content = new FormUrlEncodedContent([new("scope", "openid"), new("login_hint", "alice")]),
        });
        var authReqId = JsonDocument.Parse(await start.Content.ReadAsStringAsync())
            .RootElement.GetProperty("auth_req_id").GetString()!;
        Assert.True(await app.Services.GetRequiredService<ICibaService>().CompleteAsync(authReqId, approve: true, subject: "alice"));

        var results = await RaceAsync(() => Oidc.TokenAsync(app,
            [new("grant_type", "urn:openid:params:grant-type:ciba"), new("auth_req_id", authReqId)],
            ("ciba-client", "ciba-secret")));

        AssertExactlyOneWinner(results);
    }

    [Fact]
    public async Task PreAuthorizedCode_IsRedeemedOnce()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.VciEnabled = true;
            o.VciPreAuthorizedAnonymousAccess = true;
            o.VciCredentialConfigurations.Add(new CredentialConfiguration { Id = "Badge", Format = "jwt_vc_json" });
        });
        var offer = await app.Services.GetRequiredService<CredentialOfferService>().CreateAsync(new CredentialOfferRequest
        {
            CredentialConfigurationIds = ["Badge"],
            PreAuthorizedSubject = "alice",
        });

        var results = await RaceAsync(() => app.Client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code"),
            new("pre-authorized_code", offer.PreAuthorizedCode!),
        ])));

        AssertExactlyOneWinner(results);
    }

    [Fact]
    public async Task ClientAssertion_IsAcceptedOnce()
    {
        using var rsa = RSA.Create(2048);
        await using var app = TestWebApp.Create(o => o.StaticClients =
        [
            .. o.StaticClients,
            new Client
            {
                ClientId = "pkjwt",
                TokenEndpointAuthMethod = "private_key_jwt",
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
                JwksJson = Jwks(new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = "k1" }),
            },
        ]);
        var assertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "pkjwt",
            Audience = Issuer + "/connect/token",
            Subject = new ClaimsIdentity([new Claim("sub", "pkjwt")]),
            Expires = DateTime.UtcNow.AddMinutes(2),
            Claims = new Dictionary<string, object> { ["jti"] = Guid.NewGuid().ToString() },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256),
        });

        var results = await RaceAsync(() => app.Client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("scope", "profile"),
            new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            new("client_assertion", assertion),
        ])));

        Assert.Equal(1, results.Count(s => s == HttpStatusCode.OK));
        Assert.All(results.Where(s => s != HttpStatusCode.OK), s => Assert.Equal(HttpStatusCode.Unauthorized, s));
    }

    [Fact]
    public async Task DPoPProof_IsAcceptedOnce()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await using var app = TestWebApp.Create(o => o.DPoPEnabled = true);
        var proof = DPoPProof(key, Issuer + "/connect/token");

        var results = await RaceAsync(() => Oidc.TokenAsync(app,
            [new("grant_type", "client_credentials"), new("scope", "profile")],
            ("cc-client", "cc-secret"), dpop: proof));

        AssertExactlyOneWinner(results);
    }

    private static string Jwks(RsaSecurityKey key)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        return JsonSerializer.Serialize(new { keys = new[] { new { kty = jwk.Kty, kid = jwk.Kid, n = jwk.N, e = jwk.E } } });
    }

    private static string DPoPProof(ECDsa key, string htu)
    {
        var p = key.ExportParameters(false);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString(),
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["htm"] = "POST",
                ["htu"] = htu,
            },
            TokenType = "dpop+jwt",
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, object>
                {
                    ["kty"] = "EC", ["crv"] = "P-256",
                    ["x"] = Base64UrlEncoder.Encode(p.Q.X!), ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
                },
            },
        });
    }
}
