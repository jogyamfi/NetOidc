using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.UserInfo;

/// <summary>
/// Handles GET/POST requests to the UserInfo endpoint.
/// Validates the Bearer access token and returns claims for the authenticated subject.
/// </summary>
public sealed class UserInfoEndpointHandler
{
    private readonly TokenFactory _tokenFactory;
    private readonly IOptions<ProviderOptions> _options;

    public UserInfoEndpointHandler(TokenFactory tokenFactory, IOptions<ProviderOptions> options)
    {
        _tokenFactory = tokenFactory;
        _options = options;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var token = ExtractBearerToken(context);
        if (token is null)
        {
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"NetOidc\"";
            return Results.Unauthorized();
        }

        var principal = await _tokenFactory.ValidateAccessTokenAsync(token, ct);
        if (principal is null)
        {
            context.Response.Headers.WWWAuthenticate =
                "Bearer realm=\"NetOidc\", error=\"invalid_token\"";
            return Results.Unauthorized();
        }

        var sub = principal.FindFirstValue("sub");
        if (sub is null)
            return Results.Unauthorized();

        var scopesClaim = principal.FindFirstValue("scope") ?? string.Empty;
        var scopes = scopesClaim
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .ToList()
            .AsReadOnly();

        var claims = await _options.Value.FindUserClaims(sub, scopes, ct);
        var response = new Dictionary<string, object>(claims) { ["sub"] = sub };

        return Results.Json(response);
    }

    private static string? ExtractBearerToken(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;
        return auth["Bearer ".Length..].Trim();
    }
}
