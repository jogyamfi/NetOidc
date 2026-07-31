using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Authorization;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Dcr;
using NetOidc.Provider.Discovery;
using NetOidc.Provider.Logout;
using NetOidc.Provider.Par;
using NetOidc.Provider.Token;
using NetOidc.Provider.UserInfo;


namespace NetOidc.Provider.Http;

public static class EndpointRouteBuilderExtensions
{
    /// <summary>Maps all OIDC provider endpoints onto the ASP.NET Core router.</summary>
    public static IEndpointRouteBuilder MapNetOidc(this IEndpointRouteBuilder endpoints)
    {
        var opts = endpoints.ServiceProvider
            .GetRequiredService<IOptions<ProviderOptions>>().Value;

        var discovery = endpoints.ServiceProvider.GetRequiredService<DiscoveryService>();

        // Discovery
        endpoints.MapGet(opts.DiscoveryEndpoint, () =>
            Results.Json(discovery.BuildDocument()));

        endpoints.MapGet(opts.JwksEndpoint, () =>
            Results.Json(discovery.BuildJwks()));

        // Authorization
        endpoints.MapGet(opts.AuthorizationEndpoint,
            (AuthorizationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct));

        // Token
        endpoints.MapPost(opts.TokenEndpoint,
            (TokenEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct));

        // UserInfo (GET + POST per OIDC Core §5.3)
        endpoints.MapMethods(opts.UserInfoEndpoint, ["GET", "POST"],
            (UserInfoEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct));

        // Introspection (RFC 7662)
        endpoints.MapPost(opts.IntrospectionEndpoint,
            (IntrospectionEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct));

        // Revocation (RFC 7009)
        endpoints.MapPost(opts.RevocationEndpoint,
            (RevocationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct));

        // RP-Initiated Logout (active when LogoutEnabled)
        if (opts.LogoutEnabled)
        {
            endpoints.MapMethods(opts.EndSessionEndpoint, ["GET", "POST"],
                (LogoutEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                    h.HandleAsync(ctx, ct));
        }

        // Pushed Authorization Request (RFC 9126, always mounted; handler enforces feature toggle)
        endpoints.MapPost(opts.PushedAuthorizationEndpoint,
            (ParEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct));

        // Dynamic Client Registration (RFC 7591/7592, active when DcrEnabled)
        if (opts.DcrEnabled)
        {
            var regPath = opts.RegistrationEndpoint;
            endpoints.MapPost(regPath,
                (DynamicRegistrationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                    h.HandleCreateAsync(ctx, ct));

            endpoints.MapGet(regPath + "/{clientId}",
                (DynamicRegistrationEndpointHandler h, HttpContext ctx,
                 string clientId, CancellationToken ct) =>
                    h.HandleGetAsync(ctx, clientId, ct));

            endpoints.MapMethods(regPath + "/{clientId}", ["PUT"],
                (DynamicRegistrationEndpointHandler h, HttpContext ctx,
                 string clientId, CancellationToken ct) =>
                    h.HandleUpdateAsync(ctx, clientId, ct));

            endpoints.MapDelete(regPath + "/{clientId}",
                (DynamicRegistrationEndpointHandler h, HttpContext ctx,
                 string clientId, CancellationToken ct) =>
                    h.HandleDeleteAsync(ctx, clientId, ct));
        }

        return endpoints;
    }
}
