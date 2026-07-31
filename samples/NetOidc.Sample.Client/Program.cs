using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

var oidc = builder.Configuration.GetRequiredSection("Oidc");

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme          = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority    = oidc["Authority"];
        options.ClientId     = oidc["ClientId"];
        options.ClientSecret = oidc["ClientSecret"];
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.CallbackPath = "/callback"; // must match http://localhost:3000/callback in provider
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.SaveTokens                    = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.RequireHttpsMetadata          = false; // dev only — remove in production
    });

builder.Services.AddRazorPages();
builder.Services.AddHttpClient();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();

app.Run();
