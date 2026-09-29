using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Tests;

/// <summary>
/// Spins up an in-process ASP.NET Core app with the OIDC provider configured
/// and a <c>/test/signin</c> endpoint that trusts any subject (test-only).
/// </summary>
internal sealed class TestWebApp : IAsyncDisposable
{
    private readonly WebApplication _app;
    public HttpClient Client { get; }
    public IServiceProvider Services => _app.Services;

    public static TestWebApp Create(Action<Configuration.ProviderOptions>? configure = null)
        => new(configure, null);

    public static TestWebApp Create(
        Action<Configuration.ProviderOptions>? configure,
        Action<NetOidc.Provider.Configuration.NetOidcBuilder>? configureBuilder)
        => new(configure, configureBuilder);

    private TestWebApp(
        Action<Configuration.ProviderOptions>? configure,
        Action<NetOidc.Provider.Configuration.NetOidcBuilder>? configureBuilder)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        builder.Services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie();

        var oidcBuilder = builder.Services.AddNetOidc(opts =>
        {
            opts.Issuer = "https://auth.test.example.com";
            opts.LoginPath = "/test/signin";
            // Requests arrive from loopback (see middleware below), acting as the TLS proxy.
            opts.MtlsTrustedProxies = ["127.0.0.1"];

            opts.StaticClients =
            [
                new Client
                {
                    ClientId = "test-client",
                    ClientSecret = "test-secret",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    PostLogoutRedirectUris = ["https://client.test.example.com/logout"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                new Client
                {
                    ClientId = "implicit-client",
                    ClientSecret = "implicit-secret",
                    AllowedGrantTypes = ["implicit"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                new Client
                {
                    ClientId = "hybrid-client",
                    ClientSecret = "hybrid-secret",
                    AllowedGrantTypes = ["hybrid"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                new Client
                {
                    ClientId = "cc-client",
                    ClientSecret = "cc-secret",
                    AllowedGrantTypes = ["client_credentials"],
                    AllowedScopes = ["profile"],
                    RedirectUris = [],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                // Phase 4 PAR client
                new Client
                {
                    ClientId = "par-client",
                    ClientSecret = "par-secret",
                    AllowedGrantTypes = ["authorization_code"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                // Phase 4 token-exchange client
                new Client
                {
                    ClientId = "exchange-client",
                    ClientSecret = "exchange-secret",
                    AllowedGrantTypes =
                    [
                        "authorization_code", "client_credentials",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = ["https://client.test.example.com/callback"],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                // Phase 6 device-flow client
                new Client
                {
                    ClientId = "device-client",
                    ClientSecret = "device-secret",
                    AllowedGrantTypes = ["urn:ietf:params:oauth:grant-type:device_code"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = [],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                },
                // Phase 6 CIBA client (poll mode)
                new Client
                {
                    ClientId = "ciba-client",
                    ClientSecret = "ciba-secret",
                    AllowedGrantTypes = ["urn:ietf:params:oauth:grant-type:ciba"],
                    AllowedScopes = ["openid", "profile"],
                    RedirectUris = [],
                    TokenEndpointAuthMethod = "client_secret_basic",
                    RequirePkce = false,
                    CibaDeliveryMode = "poll",
                },
            ];

            opts.Scopes =
            [
                new Scope { Name = "openid" },
                new Scope { Name = "profile" },
            ];

            opts.FindUserClaims = (sub, scopes, ct) =>
            {
                var claims = new Dictionary<string, object> { ["sub"] = sub };
                if (scopes.Contains("profile"))
                    claims["name"] = $"Test {sub}";
                return Task.FromResult<IReadOnlyDictionary<string, object>>(claims);
            };

            configure?.Invoke(opts);
        });
        configureBuilder?.Invoke(oidcBuilder);

        _app = builder.Build();

        // TestServer leaves RemoteIpAddress unset; model a direct loopback peer unless a
        // test supplies its own via the X-Test-Remote-Ip header.
        _app.Use((ctx, next) =>
        {
            ctx.Connection.RemoteIpAddress =
                System.Net.IPAddress.TryParse(ctx.Request.Headers["X-Test-Remote-Ip"], out var ip)
                    ? ip
                    : System.Net.IPAddress.Loopback;
            return next();
        });
        _app.UseCors();
        _app.UseAuthentication();

        // Test-only: sign in any subject without credentials.
        _app.MapPost("/test/signin", async (HttpContext ctx) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            var sub = form["subject"].ToString();
            var claims = new[] { new Claim(ClaimTypes.NameIdentifier, sub) };
            var identity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await ctx.SignInAsync(new ClaimsPrincipal(identity));
            ctx.Response.StatusCode = 204;
        });

        _app.MapNetOidc();

        _app.StartAsync().GetAwaiter().GetResult();

        // Use a cookie-aware handler so cookie auth is preserved across requests.
        var testServer = _app.GetTestServer();
        Client = new HttpClient(new CookieHandler(testServer.CreateHandler()))
        {
            BaseAddress = testServer.BaseAddress,
        };
    }

    /// <summary>
    /// Mints a stored End-User access token directly through the provider's own
    /// <see cref="Jose.TokenFactory"/>, bypassing the interactive authorization flow.
    /// </summary>
    public async Task<string> IssueUserAccessTokenAsync(
        string subject, string clientId, params string[] scopes)
    {
        var factory = Services.GetRequiredService<Jose.TokenFactory>();
        var store = Services.GetRequiredService<
            Abstractions.Adapters.IAdapter<AccessToken>>();
        var tokenId = Guid.NewGuid().ToString("N");
        await store.StoreAsync(tokenId, new AccessToken
        {
            TokenId = tokenId,
            GrantId = tokenId,
            ClientId = clientId,
            Subject = subject,
            Scopes = scopes,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        }, TimeSpan.FromHours(1));
        return factory.CreateAccessToken(tokenId, subject, clientId, scopes);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    /// <summary>
    /// DelegatingHandler that maintains a CookieContainer so that Set-Cookie
    /// headers are stored and resent on subsequent requests (required for
    /// cookie-based authentication in TestServer scenarios).
    /// </summary>
    private sealed class CookieHandler : DelegatingHandler
    {
        private readonly System.Net.CookieContainer _jar = new();

        public CookieHandler(HttpMessageHandler inner) : base(inner) { }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var cookieHeader = _jar.GetCookieHeader(request.RequestUri!);
            if (!string.IsNullOrEmpty(cookieHeader))
                request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

            var response = await base.SendAsync(request, ct);

            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
                foreach (var c in setCookies)
                    _jar.SetCookies(request.RequestUri!, c);

            return response;
        }
    }
}

