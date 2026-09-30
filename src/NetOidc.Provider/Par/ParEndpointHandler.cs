using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Par;

/// <summary>
/// Handles the Pushed Authorization Request endpoint (RFC 9126).
/// <c>POST /connect/par</c> — authenticates the client, validates basic authorization
/// request parameters, stores them under a <c>request_uri</c>, and returns
/// <c>{ request_uri, expires_in }</c>.
/// </summary>
internal sealed class ParEndpointHandler
{
    /// <summary>Client authentication parameters, which must never be persisted.</summary>
    private static readonly HashSet<string> ClientAuthParameters =
        new(StringComparer.OrdinalIgnoreCase) { "client_secret", "client_assertion", "client_assertion_type" };

    private readonly IOptions<ProviderOptions> _options;
    private readonly ClientAuthenticator _clientAuthenticator;
    private readonly IAdapter<PushedAuthorizationRequest> _parStore;
    private readonly RequestObjectValidator _requestObjectValidator;
    private readonly DPoP.DPopProofValidator _dpopValidator;
    private readonly Microsoft.Extensions.Logging.ILogger<ParEndpointHandler> _logger;

    public ParEndpointHandler(
        IOptions<ProviderOptions> options,
        ClientAuthenticator clientAuthenticator,
        IAdapter<PushedAuthorizationRequest> parStore,
        RequestObjectValidator requestObjectValidator,
        DPoP.DPopProofValidator dpopValidator,
        Microsoft.Extensions.Logging.ILogger<ParEndpointHandler> logger)
    {
        _dpopValidator = dpopValidator;
        _logger = logger;
        _options = options;
        _clientAuthenticator = clientAuthenticator;
        _parStore = parStore;
        _requestObjectValidator = requestObjectValidator;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.PushedAuthorizationEnabled)
            return ParError(OAuthError.InvalidRequest("Pushed authorization is not enabled"), 400);

        if (!context.Request.HasFormContentType)
            return ParError(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var client = await _clientAuthenticator.AuthenticateAsync(context, form, ct);
        if (client is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return ParError(OAuthError.InvalidClient(), 401);
        }

        var clientId = form["client_id"].ToString();
        if (!string.IsNullOrEmpty(clientId) && clientId != client.ClientId)
            return ParError(OAuthError.InvalidRequest("client_id mismatch"), 400);

        // RFC 9126 §2.1: request_uri must not be pushed.
        if (!string.IsNullOrEmpty(form["request_uri"].ToString()))
            return ParError(OAuthError.InvalidRequest("request_uri is not allowed at the PAR endpoint"), 400);

        // ── Resolve the authorization request parameters ─────────────────────
        // Client authentication parameters are never part of the stored request.
        Dictionary<string, string> paramsDict;
        var requestJwt = form["request"].ToString();
        if (!string.IsNullOrEmpty(requestJwt))
        {
            if (!opts.JarEnabled)
                return ParError(OAuthError.InvalidRequest("request parameter is not supported (JAR is disabled)"), 400);

            var (claims, jarError) = await _requestObjectValidator.ValidateAsync(
                requestJwt, client, opts.Issuer.TrimEnd('/'), ct);
            if (jarError is not null)
                return ParError(OAuthError.InvalidRequestObject(jarError), 400);

            // RFC 9101 §5 / RFC 9126 §3: only the request object's parameters are used.
            paramsDict = RequestObjectValidator.ToAuthorizationParameters(claims!);
            if (paramsDict.TryGetValue("client_id", out var jwtClientId) && jwtClientId != client.ClientId)
                return ParError(OAuthError.InvalidRequestObject(
                    "client_id in request object does not match the authenticated client"), 400);
        }
        else
        {
            if (client.RequireSignedRequestObject)
                return ParError(OAuthError.InvalidRequest("this client requires a signed request object"), 400);

            paramsDict = form.Keys
                .Where(k => !ClientAuthParameters.Contains(k))
                .ToDictionary(k => k, k => k == "resource" ? string.Join(' ', form[k].ToArray()) : form[k].ToString(), StringComparer.Ordinal);
        }
        paramsDict["client_id"] = client.ClientId;   // normalise

        // ── DPoP authorization-code binding (RFC 9449 §10.1) ─────────────────
        // A DPoP proof sent with the pushed request binds the code to its key, like dpop_jkt.
        var dpopHeader = context.Request.Headers["DPoP"].ToString();
        if (!string.IsNullOrEmpty(dpopHeader))
        {
            if (!opts.DPoPEnabled)
                return ParError(OAuthError.InvalidRequest("DPoP is not supported by this server"), 400);
            var proof = await _dpopValidator.ValidateAsync(dpopHeader, "POST",
                opts.Issuer.TrimEnd('/') + opts.PushedAuthorizationEndpoint, accessToken: null,
                clockSkewSeconds: opts.DPoPProofLifetimeSeconds,
                allowedAlgorithms: opts.FapiProfile == Configuration.FapiProfile.None ? null : RequestObjectValidator.FapiSigningAlgorithms);
            if (proof is null)
                return ParError(OAuthError.InvalidDPoPProof("DPoP proof is missing or invalid"), 400);
            if (paramsDict.TryGetValue("dpop_jkt", out var requestedJkt) && requestedJkt != proof.Thumbprint)
                return ParError(OAuthError.InvalidDPoPProof("the DPoP proof key does not match dpop_jkt"), 400);
            paramsDict["dpop_jkt"] = proof.Thumbprint;
        }

        // ── Validate the request now, not only when it is redeemed (RFC 9126 §2.1) ──
        var responseType = paramsDict.GetValueOrDefault("response_type");
        if (string.IsNullOrEmpty(responseType))
            return ParError(OAuthError.InvalidRequest("response_type is required"), 400);
        var normalizedResponseType = Authorization.AuthorizationEndpointHandler.NormalizeResponseType(responseType);
        if (!Discovery.DiscoveryService.ResponseTypesFor(opts).Contains(normalizedResponseType))
            return ParError(OAuthError.UnsupportedResponseType($"Unsupported response_type: {responseType}"), 400);
        if (!client.ResponseTypes.Any(rt => Authorization.AuthorizationEndpointHandler.NormalizeResponseType(rt) == normalizedResponseType))
            return ParError(OAuthError.UnauthorizedClient($"client may not use response_type '{responseType}'"), 400);

        var redirectUri = paramsDict.GetValueOrDefault("redirect_uri");
        if (string.IsNullOrEmpty(redirectUri) && client.RedirectUris.Count != 1)
            return ParError(OAuthError.InvalidRequest("redirect_uri is required"), 400);
        if (!string.IsNullOrEmpty(redirectUri) && !client.RedirectUris.Contains(redirectUri))
            return ParError(OAuthError.InvalidRequest("redirect_uri not registered for this client"), 400);

        var scopes = (paramsDict.GetValueOrDefault("scope") ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var registeredScopes = opts.Scopes.Select(s => s.Name).ToHashSet();
        var badScopes = scopes.Where(s => !registeredScopes.Contains(s) || !client.AllowedScopes.Contains(s)).ToList();
        if (badScopes.Count > 0)
            return ParError(OAuthError.InvalidScope($"Scope(s) not allowed: {string.Join(" ", badScopes)}"), 400);

        // ── FAPI 1.0 PAR constraints (Phase 7) ───────────────────────────────

        if (opts.FapiProfile == Configuration.FapiProfile.Fapi1Advanced)
        {
            // Public clients are not allowed to push authorization requests (FAPI 1.0 §5.2.2).
            if (client.TokenEndpointAuthMethod == "none")
                return ParError(OAuthError.InvalidClient("FAPI 1.0: public clients cannot use PAR"), 400);

            // code_challenge is required at PAR time (FAPI 1.0 §5.2.3.1).
            if (string.IsNullOrEmpty(paramsDict.GetValueOrDefault("code_challenge")))
                return ParError(OAuthError.InvalidRequest("FAPI 1.0: code_challenge is required in PAR"), 400);
        }

        // FAPI 2.0 Message Signing: the pushed request must be a signed request object.
        if (opts.FapiProfile == Configuration.FapiProfile.Fapi2MessageSigning && string.IsNullOrEmpty(requestJwt))
            return ParError(OAuthError.InvalidRequest("FAPI 2.0 Message Signing: a signed request object is required"), 400);

        var token = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var requestUri = $"urn:ietf:params:oauth:request_uri:{token}";

        var par = new PushedAuthorizationRequest
        {
            RequestUri = requestUri,
            ClientId = client.ClientId,
            ParametersJson = JsonSerializer.Serialize(paramsDict),
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.PushedAuthorizationLifetimeSeconds),
            FromRequestObject = !string.IsNullOrEmpty(requestJwt),
        };

        await _parStore.StoreAsync(
            requestUri, par,
            TimeSpan.FromSeconds(opts.PushedAuthorizationLifetimeSeconds), ct);

        Diagnostics.Log.PushedAuthorizationStored(_logger, client.ClientId);

        return Results.Json(
            new { request_uri = requestUri, expires_in = opts.PushedAuthorizationLifetimeSeconds },
            statusCode: 201);
    }

    private static IResult ParError(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
