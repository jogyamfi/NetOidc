using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.DPoP;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.UserInfo;

/// <summary>
/// Handles GET/POST requests to the UserInfo endpoint (OIDC Core §5.3).
/// Accepts live Bearer, DPoP-bound (RFC 9449) and certificate-bound (RFC 8705) access tokens
/// and reports failures with RFC 6750 §3 challenges.
/// </summary>
public sealed class UserInfoEndpointHandler
{
    private readonly AccessTokenService _accessTokens;
    private readonly IOptions<ProviderOptions> _options;
    private readonly DPopProofValidator _dpopValidator;
    private readonly ClientAuthenticator _clientAuthenticator;
    private readonly IProviderEventSink _events;
    private readonly IClientStore _clientStore;
    private readonly UserClaimsService _userClaims;
    private readonly SubjectIdentifierService _subjects;

    public UserInfoEndpointHandler(
        AccessTokenService accessTokens,
        IOptions<ProviderOptions> options,
        DPopProofValidator dpopValidator,
        ClientAuthenticator clientAuthenticator,
        IProviderEventSink events,
        IClientStore clientStore,
        UserClaimsService userClaims,
        SubjectIdentifierService subjects)
    {
        _clientStore = clientStore;
        _userClaims = userClaims;
        _subjects = subjects;
        _accessTokens = accessTokens;
        _options = options;
        _dpopValidator = dpopValidator;
        _clientAuthenticator = clientAuthenticator;
        _events = events;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        var (token, scheme) = ExtractToken(context);
        if (token is null)
            return Challenge(context, scheme ?? "Bearer", error: null, "access token is required", 401);

        var live = await _accessTokens.ValidateAsync(token, ct);
        if (live is null)
            return Challenge(context, scheme!, "invalid_token", "access token is invalid, expired or revoked", 401);
        var (principal, record) = live;

        // ── Sender constraint (RFC 9449 §7, RFC 8705 §3) ─────────────────────
        if (record.CnfJwkThumbprint is not null)
        {
            // A DPoP-bound token presented as a Bearer token is a downgrade attempt.
            if (scheme != "DPoP")
                return Challenge(context, "DPoP", "invalid_token", "DPoP-bound token must use the DPoP scheme", 401);

            var proofThumbprint = await _dpopValidator.ValidateProofAsync(
                context.Request.Headers["DPoP"].ToString(),
                context.Request.Method,
                opts.Issuer.TrimEnd('/') + opts.UserInfoEndpoint,
                accessToken: token,
                clockSkewSeconds: opts.DPoPProofLifetimeSeconds);
            if (proofThumbprint is null || proofThumbprint != record.CnfJwkThumbprint)
                return Challenge(context, "DPoP", "invalid_dpop_proof", "DPoP proof is missing or invalid", 401);
        }
        else if (scheme == "DPoP")
        {
            return Challenge(context, "Bearer", "invalid_token", "token is not DPoP-bound", 401);
        }

        if (record.CnfX5tS256 is not null)
        {
            var cert = _clientAuthenticator.GetClientCertificate(context);
            if (cert is null || ClientAuthenticator.ComputeCertThumbprint(cert) != record.CnfX5tS256)
                return Challenge(context, scheme!, "invalid_token", "token is bound to a different client certificate", 401);
        }

        // ── Authorisation ────────────────────────────────────────────────────
        if (!record.Scopes.Contains("openid") || record.Subject is null)
            return Challenge(context, scheme!, "insufficient_scope", "the openid scope is required", 403, scope: "openid");

        var client = await _clientStore.FindClientAsync(record.ClientId, ct);
        if (client is null)
            return Challenge(context, scheme!, "invalid_token", "the client of this token no longer exists", 401);

        // The local subject reaches the claims source; the client sees its own (pairwise) sub.
        var localSubject = record.Subject;
        var scopes = record.Scopes;
        var claims = await _userClaims.GetClaimsAsync(localSubject, client, scopes,
            ClaimsEngine.Parse(record.ClaimsRequest), ClaimsDestination.UserInfo, includeScopeClaims: true, ct);
        var response = new Dictionary<string, object>(claims) { ["sub"] = _subjects.Compute(localSubject, client) };

        await _events.UserInfoRequestedAsync(new UserInfoRequestedEvent(
            localSubject, scopes, DateTimeOffset.UtcNow), ct);

        return Results.Json(response);
    }

    /// <summary>
    /// Reads the token from the Authorization header. Returns the scheme ("Bearer"/"DPoP"),
    /// or <c>null</c> when absent.
    /// </summary>
    private static (string? Token, string? Scheme) ExtractToken(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (auth.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
            return (auth["DPoP ".Length..].Trim(), "DPoP");
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return (auth["Bearer ".Length..].Trim(), "Bearer");
        return (null, null);
    }

    /// <summary>Builds an RFC 6750 §3 / RFC 9449 §7.1 challenge response.</summary>
    private IResult Challenge(
        HttpContext context, string scheme, string? error, string description, int status, string? scope = null)
    {
        var parts = new List<string> { "realm=\"NetOidc\"" };
        if (error is not null)
        {
            parts.Add($"error=\"{error}\"");
            parts.Add($"error_description=\"{description}\"");
        }
        if (scope is not null) parts.Add($"scope=\"{scope}\"");
        if (scheme == "DPoP") parts.Add("algs=\"ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512\"");

        var challenges = new List<string> { $"{scheme} {string.Join(", ", parts)}" };
        // Advertise the other scheme too when DPoP is enabled and no error is being reported.
        if (error is null && _options.Value.DPoPEnabled && scheme == "Bearer")
            challenges.Add("DPoP realm=\"NetOidc\"");

        context.Response.Headers.WWWAuthenticate = challenges.ToArray();
        return Results.StatusCode(status);
    }
}
