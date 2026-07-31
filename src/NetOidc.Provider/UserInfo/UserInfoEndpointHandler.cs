using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.DPoP;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.UserInfo;

/// <summary>
/// Handles GET/POST requests to the UserInfo endpoint.
/// Validates Bearer or DPoP-bound access tokens and returns claims for the subject.
/// </summary>
public sealed class UserInfoEndpointHandler
{
    private readonly TokenFactory _tokenFactory;
    private readonly IOptions<ProviderOptions> _options;
    private readonly DPopProofValidator _dpopValidator;
    private readonly IProviderEventSink _events;

    public UserInfoEndpointHandler(
        TokenFactory tokenFactory,
        IOptions<ProviderOptions> options,
        DPopProofValidator dpopValidator,
        IProviderEventSink events)
    {
        _tokenFactory = tokenFactory;
        _options = options;
        _dpopValidator = dpopValidator;
        _events = events;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        // RFC 9449 §7.1: DPoP tokens use "Authorization: DPoP <token>".
        var (token, isDPoP) = ExtractToken(context);
        if (token is null)
        {
            context.Response.Headers.WWWAuthenticate =
                opts.DPoPEnabled ? "Bearer realm=\"NetOidc\", DPoP" : "Bearer realm=\"NetOidc\"";
            return Results.Unauthorized();
        }

        var principal = await _tokenFactory.ValidateAccessTokenAsync(token, ct);
        if (principal is null)
        {
            context.Response.Headers.WWWAuthenticate =
                "Bearer realm=\"NetOidc\", error=\"invalid_token\"";
            return Results.Unauthorized();
        }

        // Validate DPoP proof when the token was sent as a DPoP token.
        if (isDPoP || opts.DPoPEnabled)
        {
            var cnfJkt = ExtractCnfJkt(token);
            if (cnfJkt is not null)
            {
                // DPoP-bound token: the proof must be present and commit to this token.
                var dpopHeader = context.Request.Headers["DPoP"].ToString();
                var userInfoUri = opts.Issuer.TrimEnd('/') + opts.UserInfoEndpoint;
                var proofThumbprint = await _dpopValidator.ValidateProofAsync(
                    dpopHeader,
                    context.Request.Method,
                    userInfoUri,
                    accessToken: token,
                    clockSkewSeconds: opts.DPoPProofLifetimeSeconds);

                if (proofThumbprint is null || proofThumbprint != cnfJkt)
                {
                    context.Response.Headers.WWWAuthenticate =
                        "DPoP realm=\"NetOidc\", error=\"invalid_dpop_proof\"";
                    return Results.Unauthorized();
                }
            }
        }

        var sub = principal.FindFirstValue("sub");
        if (sub is null)
            return Results.Unauthorized();

        var scopesClaim = principal.FindFirstValue("scope") ?? string.Empty;
        var scopes = scopesClaim
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .ToList()
            .AsReadOnly();

        var claims = await opts.FindUserClaims(sub, scopes, ct);
        var response = new Dictionary<string, object>(claims) { ["sub"] = sub };

        await _events.UserInfoRequestedAsync(new UserInfoRequestedEvent(
            sub, scopes, DateTimeOffset.UtcNow), ct);

        return Results.Json(response);
    }

    private static (string? Token, bool IsDPoP) ExtractToken(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (auth.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
            return (auth["DPoP ".Length..].Trim(), true);
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return (auth["Bearer ".Length..].Trim(), false);
        return (null, false);
    }

    /// <summary>
    /// Reads the <c>cnf.jkt</c> claim from a JWT access token without re-validating it.
    /// Returns <c>null</c> when the claim is absent.
    /// </summary>
    private static string? ExtractCnfJkt(string rawToken)
    {
        try
        {
            var jwt = new JsonWebToken(rawToken);
            if (jwt.TryGetPayloadValue<JsonElement>("cnf", out var cnf) &&
                cnf.TryGetProperty("jkt", out var jkt))
                return jkt.GetString();
        }
        catch { /* malformed */ }
        return null;
    }
}

