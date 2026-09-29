using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Antiforgery;
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
    options.LogoutEnabled = true;

    // Return whatever is known about the user; the provider releases only the claims that the
    // granted scopes (or an explicit claims request) allow — see request.ClaimNames.
    options.FindUserClaims = (request, ct) =>
    {
        var sub = request.Subject;
        var claims = new Dictionary<string, object>
        {
            ["name"] = sub == "alice" ? "Alice Smith" : sub,
            ["given_name"] = "Alice",
            ["family_name"] = "Smith",
            ["email"] = $"{sub}@example.com",
        };
        return Task.FromResult<IReadOnlyDictionary<string, object>>(claims);
    };

    options.StaticClients =
    [
        new Client
        {
            ClientId = "sample-client",
            ClientSecret = "sample-secret",
            AllowedGrantTypes = ["authorization_code", "refresh_token"],
            AllowedScopes = ["openid", "profile", "email"],
            RedirectUris = ["http://localhost:3000/callback"],
            PostLogoutRedirectUris = ["http://localhost:3000/signout-callback-oidc"],
            TokenEndpointAuthMethod = "client_secret_basic",
            RequirePkce = true,
            // First-party sample app: no consent page is provided.
            RequireConsent = false,
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

app.MapGet("/account/login", (HttpContext ctx, IAntiforgery antiforgery, string? returnUrl) =>
{
    var enc = HtmlEncoder.Default;
    var safeReturn = enc.Encode(returnUrl ?? "/");
    var csrf = antiforgery.GetAndStoreTokens(ctx);
    return Results.Content($"""
        <!DOCTYPE html>
        <html>
        <head><title>Sign in - NetOidc Sample</title></head>
        <body>
          <h1>Sign in</h1>
          <form method="post" action="/account/login">
            <input type="hidden" name="{enc.Encode(csrf.FormFieldName)}" value="{enc.Encode(csrf.RequestToken!)}" />
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

app.MapPost("/account/login", async (HttpContext ctx, IAntiforgery antiforgery) =>
{
    // Login CSRF: refuse credentials posted from another site's form.
    try { await antiforgery.ValidateRequestAsync(ctx); }
    catch (AntiforgeryValidationException) { return Results.BadRequest("Invalid or missing antiforgery token."); }

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

// ── Logout confirmation (RP-Initiated Logout §2) ────────────────────────────
// Shown when a logout request carries no valid id_token_hint. Re-posts the original
// parameters to the end-session endpoint with confirm=true and an antiforgery token.

app.MapGet("/account/logout", (HttpContext ctx, IAntiforgery antiforgery) =>
{
    var enc = HtmlEncoder.Default;
    var csrf = antiforgery.GetAndStoreTokens(ctx);
    var hidden = string.Concat(ctx.Request.Query.Select(q =>
        $"""<input type="hidden" name="{enc.Encode(q.Key)}" value="{enc.Encode(q.Value.ToString())}" />"""));
    return Results.Content($"""
        <!DOCTYPE html>
        <html>
        <head><title>Sign out - NetOidc Sample</title></head>
        <body>
          <h1>Sign out?</h1>
          <form method="post" action="/connect/end_session">
            {hidden}
            <input type="hidden" name="{enc.Encode(csrf.FormFieldName)}" value="{enc.Encode(csrf.RequestToken!)}" />
            <input type="hidden" name="confirm" value="true" />
            <button type="submit">Sign out</button>
          </form>
        </body>
        </html>
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
