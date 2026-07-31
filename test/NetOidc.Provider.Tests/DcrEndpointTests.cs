using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetOidc.Provider.Dcr;
using Xunit;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Integration tests for Dynamic Client Registration (RFC 7591) and
/// Client Configuration Management (RFC 7592).
/// </summary>
public sealed class DcrEndpointTests : IAsyncLifetime
{
    private TestWebApp _app = null!;

    public Task InitializeAsync()
    {
        _app = TestWebApp.Create(opts =>
        {
            opts.DcrEnabled = true;
            opts.InitialAccessToken = null;  // open registration
        });
        return Task.CompletedTask;
    }

    public Task DisposeAsync() => _app.DisposeAsync().AsTask();

    // ── POST /connect/register ──────────────────────────────────────────────

    [Fact]
    public async Task Register_MinimalRequest_Returns201WithClientId()
    {
        var req = new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
        };

        var resp = await _app.Client.PostAsJsonAsync("/connect/register", req);

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var body = await resp.Content.ReadFromJsonAsync<ClientRegistrationResponse>();
        Assert.NotNull(body);
        Assert.NotEmpty(body!.ClientId);
        Assert.NotEmpty(body.RegistrationAccessToken!);
        Assert.NotEmpty(body.RegistrationClientUri);
        Assert.Equal(0, body.ClientSecretExpiresAt);
    }

    [Fact]
    public async Task Register_EchosMetadata()
    {
        var req = new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            ClientName = "Test App",
            TokenEndpointAuthMethod = "client_secret_basic",
            GrantTypes = ["authorization_code"],
            Scope = "openid profile",
        };

        var resp = await _app.Client.PostAsJsonAsync("/connect/register", req);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var body = await resp.Content.ReadFromJsonAsync<ClientRegistrationResponse>();
        Assert.Equal("Test App", body!.ClientName);
        Assert.Equal("client_secret_basic", body.TokenEndpointAuthMethod);
        Assert.Contains("authorization_code", body.GrantTypes);
        Assert.Contains("openid", body.Scope.Split(' '));
    }

    [Fact]
    public async Task Register_AuthMethodNone_NoClientSecret()
    {
        var req = new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            TokenEndpointAuthMethod = "none",
        };

        var resp = await _app.Client.PostAsJsonAsync("/connect/register", req);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var body = await resp.Content.ReadFromJsonAsync<ClientRegistrationResponse>();
        Assert.Null(body!.ClientSecret);
    }

    [Fact]
    public async Task Register_NonJson_Returns415()
    {
        var content = new StringContent("not json", System.Text.Encoding.UTF8, "text/plain");
        var resp = await _app.Client.PostAsync("/connect/register", content);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, resp.StatusCode);
    }

    [Fact]
    public async Task Register_DcrDisabled_Returns400()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DcrEnabled = false;
        });

        var req = new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] };
        var resp = await app.Client.PostAsJsonAsync("/connect/register", req);
        // When DcrEnabled = false the endpoint is not mapped — expect 404.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Register_WithInitialAccessToken_RejectsRequestWithoutToken()
    {
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DcrEnabled = true;
            opts.InitialAccessToken = "super-secret-iat";
        });

        var req = new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] };
        var resp = await app.Client.PostAsJsonAsync("/connect/register", req);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Register_WithInitialAccessToken_AcceptsValidToken()
    {
        const string iat = "super-secret-iat";
        await using var app = TestWebApp.Create(opts =>
        {
            opts.DcrEnabled = true;
            opts.InitialAccessToken = iat;
        });

        var req = new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] };
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/register")
        {
            Content = JsonContent.Create(req),
            Headers = { Authorization = new("Bearer", iat) },
        };

        var resp = await app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    // ── GET /connect/register/{clientId} ────────────────────────────────────

    [Fact]
    public async Task Get_WithValidToken_Returns200()
    {
        var (clientId, regToken, _) = await RegisterClientAsync();

        var request = new HttpRequestMessage(
            HttpMethod.Get, $"/connect/register/{clientId}")
        {
            Headers = { Authorization = new("Bearer", regToken) },
        };
        var resp = await _app.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<ClientRegistrationResponse>();
        Assert.Equal(clientId, body!.ClientId);
        // Registration access token is not echoed on GET.
        Assert.Null(body.RegistrationAccessToken);
    }

    [Fact]
    public async Task Get_WithInvalidToken_Returns401()
    {
        var (clientId, _, _) = await RegisterClientAsync();

        var request = new HttpRequestMessage(
            HttpMethod.Get, $"/connect/register/{clientId}")
        {
            Headers = { Authorization = new("Bearer", "wrong-token") },
        };
        var resp = await _app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Get_UnknownClientId_Returns401()
    {
        var request = new HttpRequestMessage(
            HttpMethod.Get, "/connect/register/unknown-client")
        {
            Headers = { Authorization = new("Bearer", "any-token") },
        };
        var resp = await _app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── PUT /connect/register/{clientId} ────────────────────────────────────

    [Fact]
    public async Task Update_ChangesClientName_Returns200()
    {
        var (clientId, regToken, _) = await RegisterClientAsync();

        var updateReq = new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            ClientName = "Updated Name",
        };
        var request = new HttpRequestMessage(
            HttpMethod.Put, $"/connect/register/{clientId}")
        {
            Content = JsonContent.Create(updateReq),
            Headers = { Authorization = new("Bearer", regToken) },
        };
        var resp = await _app.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<ClientRegistrationResponse>();
        Assert.Equal("Updated Name", body!.ClientName);
    }

    [Fact]
    public async Task Update_WithInvalidToken_Returns401()
    {
        var (clientId, _, _) = await RegisterClientAsync();

        var updateReq = new ClientRegistrationRequest { RedirectUris = [] };
        var request = new HttpRequestMessage(
            HttpMethod.Put, $"/connect/register/{clientId}")
        {
            Content = JsonContent.Create(updateReq),
            Headers = { Authorization = new("Bearer", "wrong-token") },
        };
        var resp = await _app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── DELETE /connect/register/{clientId} ─────────────────────────────────

    [Fact]
    public async Task Delete_WithValidToken_Returns204AndClientGone()
    {
        var (clientId, regToken, _) = await RegisterClientAsync();

        var deleteReq = new HttpRequestMessage(
            HttpMethod.Delete, $"/connect/register/{clientId}")
        {
            Headers = { Authorization = new("Bearer", regToken) },
        };
        var resp = await _app.Client.SendAsync(deleteReq);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Subsequent GET should return 401 (client not found).
        var getReq = new HttpRequestMessage(
            HttpMethod.Get, $"/connect/register/{clientId}")
        {
            Headers = { Authorization = new("Bearer", regToken) },
        };
        var getResp = await _app.Client.SendAsync(getReq);
        Assert.Equal(HttpStatusCode.Unauthorized, getResp.StatusCode);
    }

    // ── Discovery document ───────────────────────────────────────────────────

    [Fact]
    public async Task DiscoveryDocument_AdvertisesRegistrationEndpoint_WhenDcrEnabled()
    {
        var resp = await _app.Client.GetAsync("/.well-known/openid-configuration");
        resp.EnsureSuccessStatusCode();

        var doc = await resp.Content.ReadFromJsonAsync<JsonObject>();
        var regEp = doc!["registration_endpoint"]?.GetValue<string>();
        Assert.NotNull(regEp);
        Assert.Contains("/connect/register", regEp);
    }

    // ── Token endpoint: registered dynamic client can authenticate ───────────

    [Fact]
    public async Task DynamicClient_CanAuthenticateAtTokenEndpoint()
    {
        var (clientId, _, clientSecret) = await RegisterClientAsync(
            new ClientRegistrationRequest
            {
                RedirectUris = ["https://rp.example.com/cb"],
                GrantTypes = ["client_credentials"],
                Scope = "profile",
                TokenEndpointAuthMethod = "client_secret_basic",
            });

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = "profile",
        };
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(form),
            Headers = { Authorization = new("Basic",
                Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"))) },
        };

        var resp = await _app.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = await resp.Content.ReadFromJsonAsync<JsonObject>();
        Assert.NotNull(body!["access_token"]?.GetValue<string>());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private async Task<(string ClientId, string RegToken, string? Secret)>
        RegisterClientAsync(ClientRegistrationRequest? req = null)
    {
        req ??= new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            TokenEndpointAuthMethod = "client_secret_basic",
        };

        var resp = await _app.Client.PostAsJsonAsync("/connect/register", req);
        resp.EnsureSuccessStatusCode();

        var body = await resp.Content.ReadFromJsonAsync<ClientRegistrationResponse>();
        return (body!.ClientId, body.RegistrationAccessToken!, body.ClientSecret);
    }
}
