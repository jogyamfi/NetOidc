using System.Net;
using System.Web;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Tests;

public sealed class Phase2MiscTests
{
    private static async Task SignInAsync(HttpClient client, string subject)
    {
        var resp = await client.PostAsync("/test/signin",
            new FormUrlEncodedContent([new("subject", subject)]));
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ── RFC 9207 Issuer Identification ─────────────────────────────────────────

    [Fact]
    public async Task AuthorizationResponse_IncludesIss_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts => opts.IssuerIdentificationEnabled = true);
        await SignInAsync(app.Client, "alice");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var query = HttpUtility.ParseQueryString(
            new Uri(resp.Headers.Location!.ToString()).Query);
        Assert.Equal("https://auth.test.example.com", query["iss"]);
    }

    [Fact]
    public async Task AuthorizationResponse_OmitsIss_WhenDisabled()
    {
        await using var app = TestWebApp.Create(opts => opts.IssuerIdentificationEnabled = false);
        await SignInAsync(app.Client, "alice");

        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=test-client&response_type=code" +
            "&redirect_uri=https%3A%2F%2Fclient.test.example.com%2Fcallback" +
            "&scope=openid");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var query = HttpUtility.ParseQueryString(
            new Uri(resp.Headers.Location!.ToString()).Query);
        Assert.Null(query["iss"]);
    }

    // ── Pairwise sub identifier ────────────────────────────────────────────────

    [Fact]
    public async Task DiscoveryDocument_AdvertisesPairwiseSubjectType()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.SubjectType = "pairwise";
            opts.PairwiseSalt = "test-salt";
        });

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var body = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        var subjectTypes = body.GetProperty("subject_types_supported")
                              .EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("pairwise", subjectTypes);
    }

    // ── ClaimsEngine unit tests ────────────────────────────────────────────────

    [Fact]
    public void ClaimsEngine_Parse_ReturnsNull_ForNullInput()
    {
        Assert.Null(ClaimsEngine.Parse(null));
        Assert.Null(ClaimsEngine.Parse(""));
        Assert.Null(ClaimsEngine.Parse("not-json"));
    }

    [Fact]
    public void ClaimsEngine_Parse_ExtractsIdTokenAndUserinfoClaims()
    {
        const string claimsJson = """
            {
              "id_token": {
                "acr": {"essential": true, "values": ["urn:mace:incommon:iap:silver"]},
                "email": null
              },
              "userinfo": {
                "name": {"essential": false},
                "phone_number": null
              }
            }
            """;

        var parsed = ClaimsEngine.Parse(claimsJson);

        Assert.NotNull(parsed);
        Assert.True(parsed.IdToken.ContainsKey("acr"));
        Assert.True(parsed.IdToken["acr"].Essential);
        Assert.Contains("urn:mace:incommon:iap:silver", parsed.IdToken["acr"].Values!);
        Assert.True(parsed.IdToken.ContainsKey("email"));

        Assert.True(parsed.UserInfo.ContainsKey("name"));
        Assert.False(parsed.UserInfo["name"].Essential);
        Assert.True(parsed.UserInfo.ContainsKey("phone_number"));
    }

    [Fact]
    public void ClaimsEngine_MergeClaims_AddsRequestedClaims()
    {
        var requested = new Dictionary<string, ClaimRequest>
        {
            ["email"] = new(Essential: false, Values: null),
            ["phone"] = new(Essential: true, Values: null),
        };

        var available = new Dictionary<string, object>
        {
            ["email"] = "alice@example.com",
            ["phone"] = "+1-555-0100",
            ["address"] = "123 Main St",
        };

        var existing = new Dictionary<string, object> { ["sub"] = "alice" };

        ClaimsEngine.MergeClaims(requested, available, existing);

        Assert.Equal("alice@example.com", existing["email"]);
        Assert.Equal("+1-555-0100", existing["phone"]);
        Assert.False(existing.ContainsKey("address")); // not requested
    }

    // ── RFC 8252 native-app redirect URIs ──────────────────────────────────────

    [Fact]
    public async Task NativeApp_AllowsDifferentPort_WhenEnabled()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.AllowNativeAppRedirects = true;
            opts.StaticClients =
            [
                new NetOidc.Provider.Abstractions.Models.Client
                {
                    ClientId = "native-client",
                    ClientSecret = "native-secret",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid"],
                    RedirectUris = ["http://localhost:12345/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                .. opts.StaticClients,
            ];
        });
        await SignInAsync(app.Client, "alice");

        // Request with different port — should match via loopback comparison
        var resp = await app.Client.GetAsync(
            "/connect/authorize?client_id=native-client&response_type=code" +
            "&redirect_uri=http%3A%2F%2Flocalhost%3A54321%2Fcallback" +
            "&scope=openid");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var location = resp.Headers.Location!.ToString();
        Assert.DoesNotContain("error", location);
    }

    // ── Discovery document ─────────────────────────────────────────────────────

    [Fact]
    public async Task DiscoveryDocument_AdvertisesIntrospectionAndRevocation()
    {
        await using var app = TestWebApp.Create();

        var resp = await app.Client.GetAsync("/.well-known/openid-configuration");
        var body = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        Assert.True(body.TryGetProperty("introspection_endpoint", out _));
        Assert.True(body.TryGetProperty("revocation_endpoint", out _));
        Assert.True(body.GetProperty("claims_parameter_supported").GetBoolean());
    }
}
