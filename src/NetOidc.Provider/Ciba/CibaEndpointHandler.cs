using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Ciba;

/// <summary>
/// Handles the CIBA Backchannel Authentication endpoint (OpenID CIBA Core 1.0 §7).
/// <c>POST /connect/ciba</c> — authenticates the client, validates the (optionally signed)
/// authentication request, stores it, starts out-of-band authentication through
/// <see cref="ProviderOptions.ProcessBackchannelAuthenticationRequest"/>, and returns
/// <c>{ auth_req_id, expires_in, interval }</c>. The host resolves the request with
/// <see cref="ICibaService.CompleteAsync"/>; poll, ping and push delivery are supported.
/// </summary>
public sealed class CibaEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly ClientAuthenticator _clientAuthenticator;
    private readonly IAdapter<BackchannelAuthenticationRequest> _cibaStore;
    private readonly RequestObjectValidator _requestObjectValidator;
    private readonly TokenFactory _tokenFactory;
    private readonly IReplayCache _replayCache;
    private readonly ILogger<CibaEndpointHandler> _logger;

    public CibaEndpointHandler(
        IOptions<ProviderOptions> options,
        ClientAuthenticator clientAuthenticator,
        IAdapter<BackchannelAuthenticationRequest> cibaStore,
        RequestObjectValidator requestObjectValidator,
        TokenFactory tokenFactory,
        IReplayCache replayCache,
        ILogger<CibaEndpointHandler> logger)
    {
        _options = options;
        _clientAuthenticator = clientAuthenticator;
        _cibaStore = cibaStore;
        _requestObjectValidator = requestObjectValidator;
        _tokenFactory = tokenFactory;
        _replayCache = replayCache;
        _logger = logger;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.CibaEnabled)
            return Error(OAuthError.InvalidRequest("CIBA is not enabled"), 400);

        if (!context.Request.HasFormContentType)
            return Error(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var client = await _clientAuthenticator.AuthenticateAsync(context, form, ct);
        if (client is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return Error(OAuthError.InvalidClient(), 401);
        }

        if (!client.AllowedGrantTypes.Contains("urn:ietf:params:oauth:grant-type:ciba"))
            return Error(OAuthError.UnauthorizedClient("CIBA grant not allowed for this client"), 400);

        // ── Delivery mode (CIBA §5) ───────────────────────────────────────────
        var deliveryMode = client.CibaDeliveryMode ?? "poll";
        if (deliveryMode is not ("poll" or "ping" or "push"))
            return Error(OAuthError.UnauthorizedClient($"unsupported delivery mode '{deliveryMode}'"), 400);
        if (deliveryMode == "push" && opts.FapiProfile == FapiProfile.FapiCiba)
            return Error(OAuthError.UnauthorizedClient("FAPI-CIBA does not allow push delivery"), 400);
        if (deliveryMode != "poll" && client.CibaClientNotificationEndpoint is null)
            return Error(OAuthError.UnauthorizedClient("client has no notification endpoint registered"), 400);

        // ── Parameters: plain form, or a signed authentication request (§7.1.1) ─
        Dictionary<string, string> parameters;
        var signedRequest = form["request"].ToString();
        if (!string.IsNullOrEmpty(signedRequest))
        {
            var (claims, error) = await _requestObjectValidator.ValidateAsync(
                signedRequest, client, opts.Issuer.TrimEnd('/'), ct);
            if (error is not null)
                return Error(OAuthError.InvalidRequest(error), 400);

            // §7.1.1: iat, nbf, exp and jti are mandatory, and jti must be single-use.
            if (!claims!.ContainsKey("iat") || !claims.ContainsKey("nbf") || !claims.ContainsKey("exp") ||
                !claims.TryGetValue("jti", out var jti) || jti?.ToString() is not { Length: > 0 } jtiValue)
                return Error(OAuthError.InvalidRequest("signed authentication request must contain iat, nbf, exp and jti"), 400);
            if (!await _replayCache.TryAddAsync($"ciba-request:{client.ClientId}:{jtiValue}",
                    DateTimeOffset.UtcNow.AddMinutes(10), ct))
                return Error(OAuthError.InvalidRequest("signed authentication request has already been used"), 400);

            parameters = RequestObjectValidator.ToAuthorizationParameters(claims);
        }
        else
        {
            if (opts.FapiProfile == FapiProfile.FapiCiba)
                return Error(OAuthError.InvalidRequest("FAPI-CIBA requires a signed authentication request"), 400);
            parameters = form.Keys.ToDictionary(k => k, k => form[k].ToString(), StringComparer.Ordinal);
        }

        string Param(string name) => parameters.TryGetValue(name, out var v) ? v : string.Empty;

        // ── Hints: exactly one (§7.1) ─────────────────────────────────────────
        var loginHint = Param("login_hint");
        var idTokenHint = Param("id_token_hint");
        var loginHintToken = Param("login_hint_token");

        var hintsProvided = new[] { loginHint, idTokenHint, loginHintToken }.Count(h => !string.IsNullOrEmpty(h));
        if (hintsProvided == 0)
            return Error(OAuthError.InvalidRequest(
                "At least one of login_hint, id_token_hint, or login_hint_token is required"), 400);
        if (hintsProvided > 1)
            return Error(OAuthError.InvalidRequest(
                "Only one of login_hint, id_token_hint, login_hint_token may be provided"), 400);

        string? hintSubject = null;
        if (!string.IsNullOrEmpty(idTokenHint))
        {
            var hint = await _tokenFactory.ValidateIdTokenHintAsync(idTokenHint, ct);
            hintSubject = hint?.FindFirst("sub")?.Value;
            if (hintSubject is null)
                return Error(OAuthError.InvalidRequest("id_token_hint is invalid"), 400);
        }

        // ── Scopes ────────────────────────────────────────────────────────────
        var requestedScopes = Param("scope").Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();
        if (requestedScopes.Count == 0)
            return Error(OAuthError.InvalidRequest("scope is required"), 400);
        if (!requestedScopes.Contains("openid"))
            return Error(OAuthError.InvalidScope("openid scope is required for CIBA"), 400);

        var registeredScopes = opts.Scopes.Select(s => s.Name).ToHashSet();
        foreach (var scope in requestedScopes)
        {
            if (!registeredScopes.Contains(scope) || !client.AllowedScopes.Contains(scope))
                return Error(OAuthError.InvalidScope($"scope '{scope}' is not allowed for this client"), 400);
        }

        // ── Other parameters ──────────────────────────────────────────────────
        var clientNotificationToken = Param("client_notification_token");
        if (deliveryMode != "poll" && string.IsNullOrEmpty(clientNotificationToken))
            return Error(OAuthError.InvalidRequest("client_notification_token is required for ping and push"), 400);

        var bindingMessage = Param("binding_message");
        if (bindingMessage.Length > opts.CibaMaxBindingMessageLength)
            return Error(OAuthError.InvalidBindingMessage(
                $"binding_message must be at most {opts.CibaMaxBindingMessageLength} characters"), 400);

        var userCode = Param("user_code");
        if (client.BackchannelUserCodeParameter && string.IsNullOrEmpty(userCode))
            return Error(OAuthError.MissingUserCode("user_code is required for this client"), 400);

        var lifetime = opts.CibaAuthReqIdLifetimeSeconds;
        var requestedExpiry = Param("requested_expiry");
        if (!string.IsNullOrEmpty(requestedExpiry))
        {
            if (!int.TryParse(requestedExpiry, out var expiry) || expiry <= 0 || expiry > opts.CibaMaxRequestedExpirySeconds)
                return Error(OAuthError.InvalidRequest(
                    $"requested_expiry must be a positive integer of at most {opts.CibaMaxRequestedExpirySeconds}"), 400);
            lifetime = expiry;
        }

        var authReqId = GenerateSecureToken();
        var authRequest = new BackchannelAuthenticationRequest
        {
            AuthReqId = authReqId,
            ClientId = client.ClientId,
            DeliveryMode = deliveryMode,
            ClientNotificationToken = NullIfEmpty(clientNotificationToken),
            LoginHint = NullIfEmpty(loginHint),
            LoginHintToken = NullIfEmpty(loginHintToken),
            IdTokenHint = NullIfEmpty(idTokenHint),
            HintSubject = hintSubject,
            UserCode = NullIfEmpty(userCode),
            AcrValues = NullIfEmpty(Param("acr_values")),
            RequestedScopes = requestedScopes,
            BindingMessage = NullIfEmpty(bindingMessage),
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(lifetime),
        };

        await _cibaStore.StoreAsync(authReqId, authRequest, TimeSpan.FromSeconds(lifetime), ct);

        // Out-of-band authentication outlives this HTTP request, so it must not use its
        // cancellation token; failures are logged rather than lost.
        if (opts.ProcessBackchannelAuthenticationRequest is { } hook)
        {
            _ = Task.Run(async () =>
            {
                try { await hook(authRequest, CancellationToken.None); }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "ProcessBackchannelAuthenticationRequest failed for {AuthReqId}", authReqId);
                }
            }, CancellationToken.None);
        }

        var response = new Dictionary<string, object>
        {
            ["auth_req_id"] = authReqId,
            ["expires_in"] = lifetime,
        };
        // CIBA §7.3: interval applies to clients that poll.
        if (deliveryMode != "push")
            response["interval"] = opts.CibaPollingIntervalSeconds;
        return Results.Json(response);
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrEmpty(value) ? null : value;

    private static string GenerateSecureToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

    private static IResult Error(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
