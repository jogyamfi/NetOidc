using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;

namespace NetOidc.Provider.Federation;

/// <summary>
/// Handles <c>GET /.well-known/openid-federation</c>, returning the provider's
/// signed entity configuration (OpenID Federation 1.1 §6.2.1).
/// The response content-type is <c>application/entity-statement+jwt</c>.
/// </summary>
public sealed class FederationEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly FederationService _federationService;

    public FederationEndpointHandler(IOptions<ProviderOptions> options, FederationService federationService)
    {
        _options = options;
        _federationService = federationService;
    }

    public IResult Handle()
    {
        if (!_options.Value.FederationEnabled)
            return Results.Json(OAuthError.InvalidRequest("Federation is not enabled"), statusCode: 400);

        var jwt = _federationService.BuildEntityConfiguration();
        return Results.Content(jwt, contentType: "application/entity-statement+jwt");
    }
}
