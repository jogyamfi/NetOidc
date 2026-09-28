using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using NetOidc.Provider.Dcr;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P1.6 (dynamic client registration metadata).</summary>
public sealed class DcrSecurityTests : IAsyncLifetime
{
    private TestWebApp _app = null!;

    public Task InitializeAsync()
    {
        _app = TestWebApp.Create(o =>
        {
            o.DcrEnabled = true;
            o.InitialAccessToken = null;
        });
        return Task.CompletedTask;
    }

    public Task DisposeAsync() => _app.DisposeAsync().AsTask();

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,hi")]
    [InlineData("file:///etc/passwd")]
    [InlineData("http://rp.example.com/cb")]
    [InlineData("https://rp.example.com/cb#frag")]
    [InlineData("/relative/cb")]
    public async Task UnsafeRedirectUri_IsRejected(string uri)
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest { RedirectUris = [uri] });
        await AssertErrorAsync(resp, "invalid_redirect_uri");
    }

    [Theory]
    [InlineData("https://rp.example.com/cb")]
    [InlineData("http://127.0.0.1:8080/cb")]
    [InlineData("http://[::1]/cb")]
    [InlineData("com.example.app:/oauth2redirect")]
    public async Task AcceptableRedirectUri_IsRegistered(string uri)
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest { RedirectUris = [uri] });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    [Fact]
    public async Task MissingRedirectUris_ForCodeFlow_IsRejected()
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest());
        await AssertErrorAsync(resp, "invalid_redirect_uri");
    }

    [Theory]
    [InlineData("client_credentials")]
    [InlineData("urn:ietf:params:oauth:grant-type:token-exchange")]
    [InlineData("implicit")]
    public async Task GrantTypeOutsideAllowlist_IsRejected(string grant)
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            GrantTypes = ["authorization_code", grant],
        });
        await AssertErrorAsync(resp, "invalid_client_metadata");
    }

    [Fact]
    public async Task InconsistentResponseType_IsRejected()
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            GrantTypes = ["authorization_code"],
            ResponseTypes = ["id_token token"],
        });
        await AssertErrorAsync(resp, "invalid_client_metadata");
    }

    [Fact]
    public async Task Pkce_IsRequiredByDefault()
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] });
        var body = await resp.Content.ReadFromJsonAsync<ClientRegistrationResponse>();
        var client = await ((Abstractions.Adapters.IClientStore)_app.Services
            .GetService(typeof(Abstractions.Adapters.IClientStore))!).FindClientAsync(body!.ClientId);
        Assert.True(client!.RequirePkce);
    }

    [Fact]
    public async Task PublicClient_CannotDisablePkce()
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            TokenEndpointAuthMethod = "none",
            RequirePkce = false,
        });
        await AssertErrorAsync(resp, "invalid_client_metadata");
    }

    [Theory]
    [InlineData("https://169.254.169.254/latest/meta-data")]
    [InlineData("https://127.0.0.1/logout")]
    [InlineData("https://10.0.0.5/logout")]
    [InlineData("https://localhost/logout")]
    [InlineData("http://rp.example.com/logout")]
    public async Task InternalBackChannelLogoutUri_IsRejected(string uri)
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            BackChannelLogoutUri = uri,
        });
        await AssertErrorAsync(resp, "invalid_client_metadata");
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://rp.example.com/logout#x")]
    public async Task UnsafePostLogoutRedirectUri_IsRejected(string uri)
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            PostLogoutRedirectUris = [uri],
        });
        await AssertErrorAsync(resp, "invalid_client_metadata");
    }

    [Fact]
    public async Task ScriptLogoUri_IsRejected()
    {
        var resp = await RegisterAsync(new ClientRegistrationRequest
        {
            RedirectUris = ["https://rp.example.com/cb"],
            LogoUri = "javascript:alert(1)",
        });
        await AssertErrorAsync(resp, "invalid_client_metadata");
    }

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.20.0.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("2001:4860:4860::8888", true)]
    public void NetworkAddressPolicy_ClassifiesAddresses(string ip, bool expectedPublic)
    {
        Assert.Equal(expectedPublic, NetworkAddressPolicy.IsPublic(IPAddress.Parse(ip)));
    }

    private Task<HttpResponseMessage> RegisterAsync(ClientRegistrationRequest req) =>
        _app.Client.PostAsJsonAsync("/connect/register", req);

    private static async Task AssertErrorAsync(HttpResponseMessage resp, string error)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Assert.True(resp.StatusCode == HttpStatusCode.BadRequest, $"{(int)resp.StatusCode}: {body}");
        Assert.Equal(error, JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }
}
