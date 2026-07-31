using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Http;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o => o.LoginPath = "/account/login");

builder.Services.AddNetOidc(options =>
{    options.Issuer = "http://localhost:5001";
    options.LoginPath = "/account/login";

    options.FindUserClaims = (sub, scopes, ct) =>
    {
        var claims = new Dictionary<string, object> { ["sub"] = sub };
        if (scopes.Contains("profile"))
        {
            claims["name"] = sub == "alice" ? "Alice Smith" : sub;
            claims["given_name"] = "Alice";
            claims["family_name"] = "Smith";
        }
        if (scopes.Contains("email"))
            claims["email"] = $"{sub}@example.com";
        return Task.FromResult<IReadOnlyDictionary<string, object>>(claims);
    };

    options.StaticClients =
    [
        new Client
        {
            ClientId = "sample-client",
            ClientSecret = "sample-secret",
            AllowedGrantTypes = ["authorization_code"],
            AllowedScopes = ["openid", "profile", "email"],
            RedirectUris = ["http://localhost:3000/callback"],
            TokenEndpointAuthMethod = "client_secret_basic",
            RequirePkce = true,
        }
    ];

    options.Scopes =
    [
        new Scope { Name = "openid" },
        new Scope { Name = "profile", Description = "Profile information" },
        new Scope { Name = "email", Description = "Email address" },
    ];
})
.AddEventSink<LoggingEventSink>();

var app = builder.Build();

app.UseAuthentication();

// ── Login page ──────────────────────────────────────────────────────────────

app.MapGet("/account/login", (string? returnUrl) =>
{
    var enc = HtmlEncoder.Default;
    var safeReturn = enc.Encode(returnUrl ?? "/");
    return Results.Content($"""
        <!DOCTYPE html>
        <html>
        <head><title>Sign in - NetOidc Sample</title></head>
        <body>
          <h1>Sign in</h1>
          <form method="post" action="/account/login">
            <input type="hidden" name="returnUrl" value="{safeReturn}" />
            <label>Username: <input type="text" name="username" autocomplete="username" /></label><br />
            <label>Password: <input type="password" name="password" autocomplete="current-password" /></label><br />
            <button type="submit">Sign in</button>
          </form>
          <p><small>Demo credentials: alice / password123</small></p>
        </body>
        </html>
        """, "text/html");
});

app.MapPost("/account/login", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var username = form["username"].ToString();
    var password = form["password"].ToString();
    var returnUrl = form["returnUrl"].ToString();

    // Validate returnUrl is relative to prevent open-redirect
    if (!Uri.TryCreate(returnUrl, UriKind.Relative, out _))
        returnUrl = "/";

    // Hardcoded demo user — replace with real identity store in production
    if (username == "alice" && password == "password123")
    {
        var claims = new[] { new Claim(ClaimTypes.NameIdentifier, username) };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await ctx.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
        return Results.Redirect(returnUrl);
    }

    return Results.Content("""
        <!DOCTYPE html>
        <html><body>
          <p>Invalid credentials. <a href="/account/login">Try again</a></p>
        </body></html>
        """, "text/html");
});

app.MapNetOidc();

app.Run();

// ── Event sink ──────────────────────────────────────────────────────────────

/// <summary>Sample event sink that logs provider lifecycle events to the console.</summary>
sealed class LoggingEventSink(ILogger<LoggingEventSink> logger) : IProviderEventSink
{
    public Task TokenIssuedAsync(TokenIssuedEvent e, CancellationToken ct = default)
    {
        logger.LogInformation("Token issued: client={Client} subject={Subject} grant={Grant}",
            e.ClientId, e.Subject ?? "(none)", e.GrantType);
        return Task.CompletedTask;
    }

    public Task AuthorizationSucceededAsync(AuthorizationSucceededEvent e, CancellationToken ct = default)
    {
        logger.LogInformation("Authorization succeeded: client={Client} subject={Subject} scopes={Scopes}",
            e.ClientId, e.Subject, string.Join(" ", e.GrantedScopes));
        return Task.CompletedTask;
    }

    public Task TokenIntrospectedAsync(TokenIntrospectedEvent e, CancellationToken ct = default)
    {
        logger.LogInformation("Token introspected: caller={Caller} active={Active}",
            e.CallerClientId, e.Active);
        return Task.CompletedTask;
    }

    public Task TokenRevokedAsync(TokenRevokedEvent e, CancellationToken ct = default)
    {
        logger.LogInformation("Token revoked: caller={Caller}", e.CallerClientId);
        return Task.CompletedTask;
    }

    public Task UserInfoRequestedAsync(UserInfoRequestedEvent e, CancellationToken ct = default)
    {
        logger.LogInformation("UserInfo requested: subject={Subject}", e.Subject);
        return Task.CompletedTask;
    }
}
