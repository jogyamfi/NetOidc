using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using NetOidc.Provider.Abstractions.Adapters;

namespace NetOidc.Provider.Tests;

/// <summary>Client ID Metadata Documents (P5.6): URL client_ids resolved from a fetched document.</summary>
public sealed class ClientIdMetadataDocumentTests
{
    private const string ClientId = "https://app.example.net/oauth/client.json";
    private const string Redirect = "https://app.example.net/cb";

    private static JsonObject Document(string clientId = ClientId) => new()
    {
        ["client_id"] = clientId,
        ["client_name"] = "Example App",
        ["redirect_uris"] = new JsonArray(Redirect),
        ["grant_types"] = new JsonArray("authorization_code", "refresh_token"),
    };

    private static (FakeWeb Web, TestWebApp App) Create(JsonObject? document = null, Action<Configuration.ProviderOptions>? configure = null, TimeSpan? maxAge = null)
    {
        var web = new FakeWeb();
        web.Serve(ClientId, (document ?? Document()).ToJsonString(), maxAge: maxAge);
        var app = web.CreateApp(o =>
        {
            o.ClientIdMetadataDocumentEnabled = true;
            configure?.Invoke(o);
        });
        return (web, app);
    }

    private static Task<Abstractions.Models.Client?> FindAsync(TestWebApp app, string clientId = ClientId) =>
        app.Services.GetRequiredService<IClientStore>().FindClientAsync(clientId);

    [Fact]
    public async Task Document_ResolvesPublicClient()
    {
        var (_, app) = Create();
        await using var _ = app;

        var client = await FindAsync(app);

        Assert.NotNull(client);
        Assert.Equal("none", client.TokenEndpointAuthMethod);
        Assert.True(client.RequirePkce);
        Assert.True(client.RequireConsent);
        Assert.Equal([Redirect], client.RedirectUris);
        Assert.Equal("Example App", client.ClientName);
    }

    [Fact]
    public async Task Document_IsCached()
    {
        var (web, app) = Create();
        await using var _ = app;

        await FindAsync(app);
        await FindAsync(app);

        Assert.Single(web.Requests, r => r.AbsoluteUri == ClientId);
    }

    [Fact]
    public async Task Disabled_DoesNotFetch()
    {
        var (web, app) = Create(configure: o => o.ClientIdMetadataDocumentEnabled = false);
        await using var _ = app;

        Assert.Null(await FindAsync(app));
        Assert.Empty(web.Requests);
    }

    [Fact]
    public async Task MismatchedClientId_IsRejected()
    {
        var (_, app) = Create(Document("https://evil.example.net/client.json"));
        await using var _ = app;

        Assert.Null(await FindAsync(app));
    }

    [Fact]
    public async Task DocumentWithSecret_IsRejected()
    {
        var document = Document();
        document["client_secret"] = "s3cret";
        var (_, app) = Create(document);
        await using var _ = app;

        Assert.Null(await FindAsync(app));
    }

    [Fact]
    public async Task ClientCredentialsGrant_IsRejected()
    {
        var document = Document();
        document["grant_types"] = new JsonArray("client_credentials");
        var (_, app) = Create(document);
        await using var _ = app;

        Assert.Null(await FindAsync(app));
    }

    [Fact]
    public async Task HostNotAllowed_IsRejectedWithoutFetching()
    {
        var (web, app) = Create(configure: o => o.ClientIdMetadataDocumentAllowedHosts = ["other.example.net"]);
        await using var _ = app;

        Assert.Null(await FindAsync(app));
        Assert.Empty(web.Requests);
    }

    [Fact]
    public async Task OversizedDocument_IsRejected()
    {
        var document = Document();
        document["client_name"] = new string('x', 6000);
        var (_, app) = Create(document);
        await using var _ = app;

        Assert.Null(await FindAsync(app));
    }

    [Theory]
    [InlineData("https://app.example.net")]
    [InlineData("https://app.example.net/client.json?x=1")]
    [InlineData("http://app.example.net/client.json")]
    public async Task InvalidClientIdUrls_AreNotResolved(string clientId)
    {
        var (web, app) = Create(Document(clientId));
        await using var _ = app;
        web.Serve(clientId, Document(clientId).ToJsonString());

        Assert.Null(await FindAsync(app, clientId));
    }

    [Fact]
    public async Task AuthorizationRequest_WithDocumentClient_ReachesConsent()
    {
        var (_, app) = Create();
        await using var _ = app;
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", ClientId), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", Redirect), ("state", "s"),
            ("code_challenge", Oidc.Challenge), ("code_challenge_method", "S256"));

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.DoesNotContain("error=", resp.Headers.Location!.ToString());
        Assert.False(resp.Headers.Location!.ToString().StartsWith(Redirect, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AuthorizationRequest_UnregisteredRedirect_IsRejected()
    {
        var (_, app) = Create();
        await using var _ = app;
        await Oidc.SignInAsync(app, "alice");

        var resp = await Oidc.AuthorizeAsync(app,
            ("client_id", ClientId), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", "https://attacker.example.com/cb"),
            ("code_challenge", Oidc.Challenge), ("code_challenge_method", "S256"));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
