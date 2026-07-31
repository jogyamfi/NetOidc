using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Authorization;
using NetOidc.Provider.Ciba;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Dcr;
using NetOidc.Provider.Device;
using NetOidc.Provider.Discovery;
using NetOidc.Provider.Federation;
using NetOidc.Provider.Logout;
using NetOidc.Provider.Par;
using NetOidc.Provider.Token;
using NetOidc.Provider.UserInfo;
using NetOidc.Provider.Vci;


namespace NetOidc.Provider.Http;

public static class EndpointRouteBuilderExtensions
{
    /// <summary>Maps all OIDC provider endpoints onto the ASP.NET Core router.</summary>
    public static IEndpointRouteBuilder MapNetOidc(this IEndpointRouteBuilder endpoints)
    {
        var opts = endpoints.ServiceProvider
            .GetRequiredService<IOptions<ProviderOptions>>().Value;

        var discovery = endpoints.ServiceProvider.GetRequiredService<DiscoveryService>();

        // When CORS is enabled the caller must add app.UseCors(); we apply the named policy
        // to every mapped endpoint so browsers receive the correct CORS headers.
        const string CorsPolicyName = "NetOidcCors";

        IEndpointConventionBuilder WithCors(IEndpointConventionBuilder b) =>
            opts.CorsEnabled ? b.RequireCors(CorsPolicyName) : b;

        // Discovery
        WithCors(endpoints.MapGet(opts.DiscoveryEndpoint, () =>
            Results.Json(discovery.BuildDocument())));

        WithCors(endpoints.MapGet(opts.JwksEndpoint, () =>
            Results.Json(discovery.BuildJwks())));

        // Authorization
        WithCors(endpoints.MapGet(opts.AuthorizationEndpoint,
            (AuthorizationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        // Token
        WithCors(endpoints.MapPost(opts.TokenEndpoint,
            (TokenEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        // UserInfo (GET + POST per OIDC Core §5.3)
        WithCors(endpoints.MapMethods(opts.UserInfoEndpoint, ["GET", "POST"],
            (UserInfoEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        // Introspection (RFC 7662)
        WithCors(endpoints.MapPost(opts.IntrospectionEndpoint,
            (IntrospectionEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        // Revocation (RFC 7009)
        WithCors(endpoints.MapPost(opts.RevocationEndpoint,
            (RevocationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        // RP-Initiated Logout (active when LogoutEnabled)
        if (opts.LogoutEnabled)
        {
            WithCors(endpoints.MapMethods(opts.EndSessionEndpoint, ["GET", "POST"],
                (LogoutEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                    h.HandleAsync(ctx, ct)));
        }

        // Pushed Authorization Request (RFC 9126, always mounted; handler enforces feature toggle)
        WithCors(endpoints.MapPost(opts.PushedAuthorizationEndpoint,
            (ParEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        // Device Authorization (RFC 8628, always mounted; handler enforces feature toggle)
        WithCors(endpoints.MapPost(opts.DeviceAuthorizationEndpoint,
            (DeviceAuthorizationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        WithCors(endpoints.MapGet(opts.DeviceVerificationUri,
            (DeviceVerificationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleGetAsync(ctx, ct)));

        WithCors(endpoints.MapPost(opts.DeviceVerificationUri,
            (DeviceVerificationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandlePostAsync(ctx, ct)));

        // CIBA — Backchannel Authentication (always mounted; handler enforces feature toggle)
        WithCors(endpoints.MapPost(opts.BackchannelAuthenticationEndpoint,
            (CibaEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleAsync(ctx, ct)));

        // Dynamic Client Registration (RFC 7591/7592, active when DcrEnabled)
        if (opts.DcrEnabled)
        {
            var regPath = opts.RegistrationEndpoint;
            WithCors(endpoints.MapPost(regPath,
                (DynamicRegistrationEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                    h.HandleCreateAsync(ctx, ct)));

            WithCors(endpoints.MapGet(regPath + "/{clientId}",
                (DynamicRegistrationEndpointHandler h, HttpContext ctx,
                 string clientId, CancellationToken ct) =>
                    h.HandleGetAsync(ctx, clientId, ct)));

            WithCors(endpoints.MapMethods(regPath + "/{clientId}", ["PUT"],
                (DynamicRegistrationEndpointHandler h, HttpContext ctx,
                 string clientId, CancellationToken ct) =>
                    h.HandleUpdateAsync(ctx, clientId, ct)));

            WithCors(endpoints.MapDelete(regPath + "/{clientId}",
                (DynamicRegistrationEndpointHandler h, HttpContext ctx,
                 string clientId, CancellationToken ct) =>
                    h.HandleDeleteAsync(ctx, clientId, ct)));
        }

        // ── Phase 8 — OpenID Federation 1.1 ──────────────────────────────────
        // Always mounted; handler returns 400 when FederationEnabled is false.
        WithCors(endpoints.MapGet("/.well-known/openid-federation",
            (FederationEndpointHandler h) => h.Handle()));

        // ── Phase 8 — VCI (OID4VCI 1.0) ──────────────────────────────────────
        // Always mounted; handlers return 400 when VciEnabled is false.
        WithCors(endpoints.MapPost(opts.VciNonceEndpoint,
            (VciEndpointHandler h) => h.HandleNonce()));

        WithCors(endpoints.MapPost(opts.VciCredentialEndpoint,
            (VciEndpointHandler h, HttpContext ctx, CancellationToken ct) =>
                h.HandleCredentialAsync(ctx, ct)));

        // Credential issuer metadata (OID4VCI §11.2)
        WithCors(endpoints.MapGet("/.well-known/openid-credential-issuer",
            (VciEndpointHandler h, HttpContext ctx) =>
            {
                var o = ctx.RequestServices.GetRequiredService<IOptions<ProviderOptions>>().Value;
                if (!o.VciEnabled)
                    return Results.Json(Errors.OAuthError.InvalidRequest("VCI is not enabled"), statusCode: 400);

                var issuer = (string.IsNullOrEmpty(o.VciCredentialIssuer) ? o.Issuer : o.VciCredentialIssuer).TrimEnd('/');
                string Abs(string p) => issuer + p;

                var configs = o.VciCredentialConfigurations.ToDictionary(
                    c => c.Id,
                    c => (object)new
                    {
                        format = c.Format,
                        scope = c.Scope,
                        credential_signing_alg_values_supported = c.CredentialSigningAlgValuesSupported,
                        cryptographic_binding_methods_supported = c.CryptographicBindingMethodsSupported,
                        proof_types_supported = c.ProofTypesSupported.ToDictionary(
                            kv => kv.Key,
                            kv => (object)new { proof_signing_alg_values_supported = kv.Value }),
                        vct = c.Vct,
                    });

                return Results.Json(new
                {
                    credential_issuer = issuer,
                    credential_endpoint = Abs(o.VciCredentialEndpoint),
                    nonce_endpoint = Abs(o.VciNonceEndpoint),
                    credential_configurations_supported = configs,
                });
            }));

        // ── Phase 8 — Client ID Metadata Document ─────────────────────────────
        WithCors(endpoints.MapGet("/.well-known/client_id_metadata/{clientId}",
            (ClientIdMetadataEndpointHandler h, string clientId, CancellationToken ct) =>
                h.HandleAsync(clientId, ct)));

        return endpoints;
    }
}