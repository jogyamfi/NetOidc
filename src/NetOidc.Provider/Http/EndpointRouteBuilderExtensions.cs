using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Authorization;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Discovery;
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

        return endpoints;
    }
}
