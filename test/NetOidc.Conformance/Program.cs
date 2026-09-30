using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Conformance;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;
using NetOidc.Provider.Interaction;

// NetOidc OpenID Provider configured for the OpenID Foundation conformance suite.
// See README.md: run with --Conformance:Profile=<profile> and point the suite at the plan
// configuration under plans/.

var builder = WebApplication.CreateBuilder(args);
var settings = builder.Configuration.GetSection("Conformance").Get<ConformanceSettings>() ?? new ConformanceSettings();
var profile = ConformanceProfiles.Parse(settings.Profile);
var clientKeys = new ClientCredentialStore();

// ── HTTPS (and client certificates for the mTLS profiles) ───────────────────
builder.WebHost.ConfigureKestrel(kestrel =>
{
    var tls = SelfSignedCertificate(new Uri(settings.Issuer).Host);
    kestrel.Listen(IPAddress.Any, new Uri(settings.Issuer).Port, listen => listen.UseHttps(https =>
    {
        https.ServerCertificate = tls;
        // Never TLS 1.0/1.1 (RFC 8996).
        https.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13;
        if (profile.UsesMtls)
        {
            // FAPI 2.0 §5.2.1/§5.2.2 (BCP 195): TLS 1.2 with a short cipher list, or TLS 1.3.
            // Kestrel cannot restrict TLS 1.2 ciphers on Windows, so the FAPI host uses TLS 1.3.
            https.SslProtocols = System.Security.Authentication.SslProtocols.Tls13;
            // The provider validates client certificates itself (RFC 8705); accept any here.
            https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
            https.AllowAnyClientCertificate();
        }
    }));
});

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/account/login";
        o.Cookie.SameSite = SameSiteMode.None;   // the suite posts back cross-site (form_post, logout)
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    });

builder.Services.AddAuthorization();

// Fresh keys per run: the suite reads the JWKS for every test.
var rsa = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "rs256" };
var ps = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "ps256" };
var ec = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = "es256" };
var enc = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "enc" };

var oidc = builder.Services.AddNetOidc(options =>
    {
        options.Issuer = settings.Issuer;
        options.DefaultSigningAlgorithm = profile.DefaultSigningAlgorithm;
        options.LoginPath = "/account/login";
        options.ConsentPath = "/account/consent";
        options.Scopes = [.. ConformanceUser.Scopes];
        options.FindUserClaims = (request, _) =>
            Task.FromResult<IReadOnlyDictionary<string, object>>(ConformanceUser.Claims(request.Subject));
        // Errors that cannot go back to the client are shown to the End-User; the suite's
        // browser automation recognises this page (see SuiteBrowser.cs).
        options.RenderErrorPage = (_, error) => Task.FromResult<IResult>(Results.Content($"""
            <!DOCTYPE html>
            <html><head><title>Error - NetOidc conformance</title></head>
            <body><h1>NetOidc error</h1>
              <p id="error">{HtmlEncoder.Default.Encode(error.Error)}</p>
              <p id="error_description">{HtmlEncoder.Default.Encode(error.Description ?? "")}</p>
            </body></html>
            """, "text/html", statusCode: 400));
        profile.Configure(options, settings, clientKeys);
    })
    // The default algorithm's key signs unless a client asks for another. FAPI allows only
    // PS256 and ES256, so RS256 is registered for the OpenID Connect profile alone.
    .AddSigningKey(profile.DefaultSigningAlgorithm == "RS256" ? rsa : ps, profile.DefaultSigningAlgorithm)
    .AddSigningKey(profile.DefaultSigningAlgorithm == "RS256" ? ps : ec, profile.DefaultSigningAlgorithm == "RS256" ? "PS256" : "ES256")
    .AddEncryptionKey(enc);
if (profile.DefaultSigningAlgorithm == "RS256")
    oidc.AddSigningKey(ec, "ES256");

// The local suite serves a self-signed certificate. Trust it for the suite's host only, for the
// provider's calls to it (jwks_uri, request_uri, logout and CIBA notifications); every other
// destination keeps normal certificate validation.
var suiteHost = new Uri(settings.SuiteBaseUrl).Host;
builder.Services.AddHttpClient(NetOidcHttpClients.Trusted)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        SslOptions = new System.Net.Security.SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (request, _, _, errors) =>
                errors == System.Net.Security.SslPolicyErrors.None ||
                (request is System.Net.Security.SslStream stream && stream.TargetHostName == suiteHost),
        },
    });

var app = builder.Build();
CibaDevice.Services = app.Services;

// The suite needs the clients' private keys and certificates: write its plan configurations.
if (settings.SuiteConfigDir is { Length: > 0 } configDir)
{
    Directory.CreateDirectory(configDir);
    foreach (var (file, config) in profile.SuiteConfigs(settings, clientKeys))
        File.WriteAllText(Path.Combine(configDir, file),
            config.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
}

app.UseAuthentication();
app.UseAuthorization();

// ── Login: any submission signs in the conformance user ─────────────────────
// The suite's browser automation fills the form (see plans/*.json "browser").

app.MapGet("/account/login", (HttpContext ctx, IAntiforgery antiforgery, string? returnUrl, string? acr_values) =>
{
    var html = HtmlEncoder.Default;
    var csrf = antiforgery.GetAndStoreTokens(ctx);
    return Results.Content($"""
        <!DOCTYPE html>
        <html><head><title>Sign in - NetOidc conformance</title></head>
        <body>
          <h1>Sign in</h1>
          <form method="post" action="/account/login">
            <input type="hidden" name="{html.Encode(csrf.FormFieldName)}" value="{html.Encode(csrf.RequestToken!)}" />
            <input type="hidden" name="returnUrl" value="{html.Encode(returnUrl ?? "/")}" />
            <input type="hidden" name="acr" value="{html.Encode(acr_values?.Split(' ')[0] ?? "")}" />
            <input type="text" id="username" name="username" value="{ConformanceUser.Subject}" />
            <input type="password" id="password" name="password" value="password" />
            <button type="submit" id="login-submit" class="login-submit">Sign in</button>
            <button type="submit" id="login-cancel" name="action" value="cancel">Cancel</button>
          </form>
        </body></html>
        """, "text/html");
});

app.MapPost("/account/login", async (HttpContext ctx, IAntiforgery antiforgery, InteractionDenialService denials) =>
{
    try { await antiforgery.ValidateRequestAsync(ctx); }
    catch (AntiforgeryValidationException) { return Results.BadRequest("Invalid or missing antiforgery token."); }

    var form = await ctx.Request.ReadFormAsync();
    var returnUrl = form["returnUrl"].ToString();
    if (!returnUrl.StartsWith('/') || returnUrl.StartsWith("//", StringComparison.Ordinal))
        returnUrl = "/";

    // The End-User cancelled: the client receives access_denied (OIDC Core §3.1.2.6).
    if (form["action"] == "cancel")
    {
        await denials.DenyAsync(returnUrl);
        return Results.Redirect(returnUrl);
    }

    var identity = new ClaimsIdentity(
    [
        new Claim(ClaimTypes.NameIdentifier, ConformanceUser.Subject),
        new Claim("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        // The login "achieves" the first requested acr value, as a real step-up would.
        new Claim("acr", form["acr"] is { Count: > 0 } acr && acr[0] is { Length: > 0 } a ? a : "urn:netoidc:acr:password"),
        new Claim("amr", "pwd"),
    ], CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(new ClaimsPrincipal(identity));
    return Results.Redirect(returnUrl);
});

// ── Consent (dynamically registered clients always require it) ──────────────

app.MapGet("/account/consent", async (HttpContext ctx, IAntiforgery antiforgery, IClientStore clients,
    string? returnUrl, string? client_id, string? scope) =>
{
    var html = HtmlEncoder.Default;
    var csrf = antiforgery.GetAndStoreTokens(ctx);
    // OIDC Registration §2: show the client's name, logo, policy and terms to the End-User.
    var client = client_id is null ? null : await clients.FindClientAsync(client_id);
    string Link(string? uri, string text) =>
        uri is null ? "" : $"""<p><a href="{html.Encode(uri)}">{text}</a></p>""";
    var metadata = client is null ? "" :
        (client.LogoUri is null ? "" : $"""<p><img src="{html.Encode(client.LogoUri)}" alt="logo" /></p>""") +
        Link(client.ClientUri, "Client home page") + Link(client.PolicyUri, "Privacy policy") + Link(client.TosUri, "Terms of service");
    return Results.Content($"""
        <!DOCTYPE html>
        <html><head><title>Consent - NetOidc conformance</title></head>
        <body>
          <h1>Allow {html.Encode(client?.ClientName ?? client_id ?? "")} to access: {html.Encode(scope ?? "")}?</h1>
          {metadata}
          <form method="post" action="/account/consent">
            <input type="hidden" name="{html.Encode(csrf.FormFieldName)}" value="{html.Encode(csrf.RequestToken!)}" />
            <input type="hidden" name="returnUrl" value="{html.Encode(returnUrl ?? "/")}" />
            <input type="hidden" name="client_id" value="{html.Encode(client_id ?? "")}" />
            <input type="hidden" name="scope" value="{html.Encode(scope ?? "")}" />
            <button type="submit" id="consent-submit" class="login-submit">Allow</button>
          </form>
        </body></html>
        """, "text/html");
}).RequireAuthorization();

app.MapPost("/account/consent", async (HttpContext ctx, IAntiforgery antiforgery, ConsentService consents) =>
{
    try { await antiforgery.ValidateRequestAsync(ctx); }
    catch (AntiforgeryValidationException) { return Results.BadRequest("Invalid or missing antiforgery token."); }

    var form = await ctx.Request.ReadFormAsync();
    var subject = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
    await consents.GrantAsync(form["client_id"].ToString(), subject,
        form["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries));
    var returnUrl = form["returnUrl"].ToString();
    return Results.Redirect(returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal) ? returnUrl : "/");
}).RequireAuthorization();

// ── Logout confirmation and the logged-out page ─────────────────────────────

app.MapGet("/account/logout", (HttpContext ctx, IAntiforgery antiforgery) =>
{
    var html = HtmlEncoder.Default;
    var csrf = antiforgery.GetAndStoreTokens(ctx);
    var hidden = string.Concat(ctx.Request.Query.Select(q =>
        $"""<input type="hidden" name="{html.Encode(q.Key)}" value="{html.Encode(q.Value.ToString())}" />"""));
    return Results.Content($"""
        <!DOCTYPE html>
        <html><head><title>Sign out - NetOidc conformance</title></head>
        <body>
          <h1>Sign out?</h1>
          <form method="post" action="{settings.EndSessionPath}">
            {hidden}
            <input type="hidden" name="{html.Encode(csrf.FormFieldName)}" value="{html.Encode(csrf.RequestToken!)}" />
            <input type="hidden" name="confirm" value="true" />
            <button type="submit" id="logout-submit" autofocus>Sign out</button>
          </form>
        </body></html>
        """, "text/html");
});

app.MapGet("/", () => Results.Content(
    "<!DOCTYPE html><html><body><h1>NetOidc conformance OP</h1><p>You are signed out.</p></body></html>", "text/html"));

app.MapNetOidc();

app.Run();

static X509Certificate2 SelfSignedCertificate(string host)
{
    using var key = RSA.Create(2048);
    var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName(host);
    san.AddDnsName("localhost");
    request.CertificateExtensions.Add(san.Build());
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
    using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    // Re-import so the private key is usable by SslStream on every platform.
    return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12), null);
}
