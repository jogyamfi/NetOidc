using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Interaction;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Session;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Authorization;

/// <summary>
/// Handles GET and POST requests to the authorization endpoint (OIDC Core §3.1.2.1).
/// Supports authorization_code, implicit and hybrid flows, PAR (RFC 9126), JAR (RFC 9101),
/// JARM, resource indicators (RFC 8707), rich authorization requests (RFC 9396), the OIDC
/// <c>prompt</c>/<c>max_age</c>/<c>id_token_hint</c>/<c>claims</c> parameters and FAPI profiles.
/// </summary>
internal sealed class AuthorizationEndpointHandler
{
    private const string InteractionParameter = "interaction";

    private static readonly HashSet<string> KnownResponseTypes =
    [
        "code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token",
    ];

    private static readonly HashSet<string> KnownPrompts = ["none", "login", "consent", "select_account"];

    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly IAdapter<AuthorizationCode> _codeStore;
    private readonly IAdapter<PushedAuthorizationRequest> _parStore;
    private readonly IAdapter<PendingInteraction> _interactions;
    private readonly IInteractionService _interactionService;
    private readonly TokenFactory _tokenFactory;
    private readonly TokenIssuanceService _issuer;
    private readonly GrantService _grants;
    private readonly SubjectIdentifierService _subjects;
    private readonly SessionService _sessionService;
    private readonly RequestObjectValidator _requestObjectValidator;
    private readonly IProviderEventSink _events;
    private readonly Microsoft.Extensions.Logging.ILogger<AuthorizationEndpointHandler> _logger;

    public AuthorizationEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        IAdapter<AuthorizationCode> codeStore,
        IAdapter<PushedAuthorizationRequest> parStore,
        IAdapter<PendingInteraction> interactions,
        IInteractionService interactionService,
        TokenFactory tokenFactory,
        TokenIssuanceService issuer,
        GrantService grants,
        SubjectIdentifierService subjects,
        SessionService sessionService,
        RequestObjectValidator requestObjectValidator,
        IProviderEventSink events,
        Microsoft.Extensions.Logging.ILogger<AuthorizationEndpointHandler> logger)
    {
        _logger = logger;
        _options = options;
        _clientStore = clientStore;
        _codeStore = codeStore;
        _parStore = parStore;
        _interactions = interactions;
        _interactionService = interactionService;
        _tokenFactory = tokenFactory;
        _issuer = issuer;
        _grants = grants;
        _subjects = subjects;
        _sessionService = sessionService;
        _requestObjectValidator = requestObjectValidator;
        _events = events;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var result = await HandleCoreAsync(context, ct);
        await RecordOutcomeAsync(context, result, ct);

        // Errors that cannot be redirected to the client are shown to the End-User.
        if (_options.Value.RenderErrorPage is { } render &&
            result is Microsoft.AspNetCore.Http.HttpResults.BadRequest<OAuthError> { Value: { } error })
            return await render(context, error);
        return result;
    }

    /// <summary>Logs, counts and raises an event for the authorization outcome.</summary>
    private async Task RecordOutcomeAsync(HttpContext context, IResult result, CancellationToken ct)
    {
        var opts = _options.Value;
        var clientId = context.Request.Query["client_id"].ToString();
        if (string.IsNullOrEmpty(clientId) && context.Request.HasFormContentType)
            clientId = context.Request.Form["client_id"].ToString();

        string? error = null, description = null;
        switch (result)
        {
            case Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult redirect
                when redirect.Url.StartsWith(opts.LoginPath, StringComparison.Ordinal) ||
                     redirect.Url.StartsWith(opts.ConsentPath, StringComparison.Ordinal):
                Diagnostics.Log.AuthorizationSuspended(_logger, clientId,
                    redirect.Url.StartsWith(opts.ConsentPath, StringComparison.Ordinal) ? "consent" : "login");
                return;
            case Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult redirect:
                var uri = new Uri(new Uri("https://client.invalid"), redirect.Url);
                var response = QueryHelpers.ParseQuery(uri.Fragment.Length > 1 ? uri.Fragment[1..] : uri.Query);
                if (response.TryGetValue("error", out var e))
                {
                    error = e.ToString();
                    description = response.TryGetValue("error_description", out var d) ? d.ToString() : null;
                }
                break;
            case Microsoft.AspNetCore.Http.HttpResults.BadRequest<OAuthError> { Value: { } page }:
                (error, description) = (page.Error, page.Description);
                break;
            case Microsoft.AspNetCore.Http.HttpResults.ContentHttpResult { ResponseContent: { } html }
                when html.Contains("name=\"error\"", StringComparison.Ordinal):
                error = "error";
                break;
        }

        Diagnostics.NetOidcTelemetry.Authorizations.Add(1,
            new KeyValuePair<string, object?>("outcome", error ?? "success"));
        if (error is null)
        {
            Diagnostics.Log.AuthorizationCompleted(_logger, clientId);
            return;
        }
        Diagnostics.Log.AuthorizationFailed(_logger, NullIfEmpty(clientId), error, description);
        await _events.AuthorizationFailedAsync(
            new AuthorizationFailedEvent(NullIfEmpty(clientId), error, description, DateTimeOffset.UtcNow), ct);
    }

    private async Task<IResult> HandleCoreAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        // OIDC Core §3.1.2.1: parameters arrive as query (GET) or form body (POST).
        var raw = await ReadRawParametersAsync(context, ct);

        var clientId = GetParam(raw, "client_id");
        if (string.IsNullOrEmpty(clientId))
            return ShowErrorPage("client_id is required");

        var client = await _clientStore.FindClientAsync(clientId, ct);
        if (client is null)
            return ShowErrorPage("unknown client_id");

        // ── PAR / JAR — resolve effective parameters ──────────────────────────
        var resolved = await ResolveParametersAsync(raw, client, opts, ct);
        var effectiveParams = resolved.Params;
        if (resolved.Error is not null)
        {
            // The redirect URI comes only from the (verified) request and must be registered.
            var knownRedirect = GetParam(effectiveParams, "redirect_uri");
            var delivery = WithRequestObjectHints(effectiveParams);
            if (!string.IsNullOrEmpty(knownRedirect) && IsValidRedirectUri(client, knownRedirect))
                return SendError(knownRedirect, GetParam(delivery, "state"), ErrorResponseMode(delivery), resolved.Error,
                    ErrorJarmClient(delivery, client));
            return ShowErrorPage(resolved.Error.Description ?? resolved.Error.Error);
        }

        var redirectUri = GetParam(effectiveParams, "redirect_uri");
        var redirectUriInRequest = !string.IsNullOrEmpty(redirectUri);
        if (string.IsNullOrEmpty(redirectUri))
        {
            if (client.RedirectUris.Count == 1)
                redirectUri = client.RedirectUris[0];
            else
                return ShowErrorPage("redirect_uri is required");
        }

        if (!IsValidRedirectUri(client, redirectUri))
            return ShowErrorPage("redirect_uri not registered for this client");

        var rawResponseType = GetParam(effectiveParams, "response_type");
        var scope = GetParam(effectiveParams, "scope");
        var state = GetParam(effectiveParams, "state");
        var nonce = GetParam(effectiveParams, "nonce");
        var responseMode = GetParam(effectiveParams, "response_mode");
        var codeChallenge = GetParam(effectiveParams, "code_challenge");
        var codeChallengeMethod = GetParam(effectiveParams, "code_challenge_method");
        var claimsParam = GetParam(effectiveParams, "claims");

        // ── Response type (RFC 7591 response_types / grant_types) ─────────────
        var normalizedResponseType = NormalizeResponseType(rawResponseType);
        // Response types the server does not offer (per FAPI profile, as in discovery) are
        // unsupported_response_type; unauthorized_client is for ones the client may not use.
        if (!KnownResponseTypes.Contains(normalizedResponseType) ||
            !Discovery.DiscoveryService.ResponseTypesFor(opts).Contains(normalizedResponseType))
            return SendError(redirectUri, state, ErrorResponseMode(effectiveParams),
                OAuthError.UnsupportedResponseType($"Unsupported response_type: {rawResponseType}" + opts.FapiProfile switch
                {
                    FapiProfile.Fapi1Advanced => " (FAPI 1.0 Advanced profile)",
                    FapiProfile.Fapi2Security or FapiProfile.Fapi2MessageSigning => " (FAPI 2.0 profile)",
                    FapiProfile.FapiCiba => " (FAPI-CIBA profile)",
                    _ => "",
                }), ErrorJarmClient(effectiveParams, client));

        var responseTokens = normalizedResponseType.Split(' ');
        var includesCode = responseTokens.Contains("code");
        var includesIdToken = responseTokens.Contains("id_token");
        var includesToken = responseTokens.Contains("token");
        var isCode = normalizedResponseType == "code";

        if (!client.ResponseTypes.Any(rt => NormalizeResponseType(rt) == normalizedResponseType) ||
            (includesCode && !client.AllowedGrantTypes.Contains("authorization_code")) ||
            ((includesIdToken || includesToken) && !isCode && !client.AllowedGrantTypes.Contains("implicit")))
            return SendError(redirectUri, state, ErrorResponseMode(effectiveParams),
                OAuthError.UnauthorizedClient($"client may not use response_type '{rawResponseType}'"),
                ErrorJarmClient(effectiveParams, client));

        // ── Response mode (plain + JARM) ──────────────────────────────────────
        var (baseMode, useJarm) = ParseResponseMode(responseMode, isCode, opts);
        if (baseMode is null)
            return SendError(redirectUri, state, ErrorResponseMode(effectiveParams),
                OAuthError.InvalidRequest($"Unsupported response_mode: {responseMode}"),
                ErrorJarmClient(effectiveParams, client));

        // Tokens must never travel in the query string.
        if (baseMode == "query" && !isCode && !useJarm)
            return SendError(redirectUri, state, baseMode,
                OAuthError.InvalidRequest("response_mode=query is not permitted when tokens are returned"));

        // Every error from here on is returned the way the client asked for responses.
        IResult Fail(OAuthError error) => SendError(redirectUri, state, baseMode, error, useJarm ? client : null);

        // ── Scopes ────────────────────────────────────────────────────────────
        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();

        var registeredScopes = opts.Scopes.Select(s => s.Name).ToHashSet();
        var unknownScopes = requestedScopes.Where(s => !registeredScopes.Contains(s)).ToList();
        if (unknownScopes.Count > 0)
            return Fail(OAuthError.InvalidScope($"Unknown scope(s): {string.Join(" ", unknownScopes)}"));

        var disallowedScopes = requestedScopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
        if (disallowedScopes.Count > 0)
            return Fail(OAuthError.InvalidScope($"Client not authorized for: {string.Join(" ", disallowedScopes)}"));

        var isOpenId = requestedScopes.Contains("openid");
        if (includesIdToken && !isOpenId)
            return Fail(OAuthError.InvalidScope("response_type id_token requires the openid scope"));

        // OIDC Core §3.2.2.1 / §3.3.2.11: nonce is required when an id_token is returned directly.
        if (includesIdToken && string.IsNullOrEmpty(nonce))
            return Fail(OAuthError.InvalidRequest("nonce is required when response_type includes id_token"));

        // ── PKCE (RFC 7636, RFC 9700 §2.1.1) ──────────────────────────────────
        if (includesCode)
        {
            var pkceRequired = client.RequirePkce || client.TokenEndpointAuthMethod == "none";
            if (pkceRequired && string.IsNullOrEmpty(codeChallenge))
                return Fail(OAuthError.InvalidRequest("code_challenge is required (PKCE)"));

            if (!string.IsNullOrEmpty(codeChallenge))
            {
                if (string.IsNullOrEmpty(codeChallengeMethod))
                {
                    if (!opts.AllowPlainPkce)
                        return Fail(OAuthError.InvalidRequest("code_challenge_method is required; use S256"));
                    codeChallengeMethod = "plain";
                }

                if (codeChallengeMethod == "plain" ? !opts.AllowPlainPkce : codeChallengeMethod != "S256")
                    return Fail(OAuthError.InvalidRequest("Unsupported code_challenge_method; use S256"));

                if (!PkceValidator.IsWellFormed(codeChallenge))
                    return Fail(OAuthError.InvalidRequest("code_challenge must be 43-128 unreserved characters"));
            }
        }

        // ── FAPI profile runtime enforcement ──────────────────────────────────
        if (opts.FapiProfile == FapiProfile.Fapi1Advanced)
        {
            // FAPI 1.0 Advanced §5.2.2: code or code id_token; JARM for code; nonce for OpenID;
            // a signed request object (directly or pushed).
            if (!isCode && normalizedResponseType != "code id_token")
                return Fail(OAuthError.InvalidRequest("FAPI 1.0: response_type must be 'code' or 'code id_token'"));
            if (isCode && !useJarm)
                return Fail(OAuthError.InvalidRequest("FAPI 1.0: response_mode=jwt is required when response_type is 'code'"));
            if (isOpenId && string.IsNullOrEmpty(nonce))
                return Fail(OAuthError.InvalidRequest("FAPI 1.0: nonce is required for OpenID requests"));
            if (!resolved.FromRequestObject && !resolved.FromPar)
                return Fail(OAuthError.InvalidRequest("FAPI 1.0: a request object or pushed authorization request is required"));
        }

        if (opts.FapiProfile is FapiProfile.Fapi2Security or FapiProfile.Fapi2MessageSigning or FapiProfile.FapiCiba)
        {
            // FAPI 2.0 §5.3.1: code only, PKCE S256, pushed authorization requests.
            if (!isCode)
                return Fail(OAuthError.InvalidRequest("FAPI 2.0: response_type must be 'code'"));
            if (string.IsNullOrEmpty(codeChallenge) || codeChallengeMethod != "S256")
                return Fail(OAuthError.InvalidRequest("FAPI 2.0: code_challenge with S256 is required"));
            if (!resolved.FromPar)
                return Fail(OAuthError.InvalidRequest("FAPI 2.0: pushed authorization requests are required"));

            // FAPI 2.0 Message Signing: signed requests and signed responses.
            if (opts.FapiProfile == FapiProfile.Fapi2MessageSigning)
            {
                if (!resolved.FromRequestObject)
                    return Fail(OAuthError.InvalidRequest("FAPI 2.0 Message Signing: a signed request object is required"));
                if (!useJarm)
                    return Fail(OAuthError.InvalidRequest("FAPI 2.0 Message Signing: response_mode=jwt is required"));
            }
        }

        // ── OIDC request parameters (§3.1.2.1) ────────────────────────────────
        var prompt = GetParam(effectiveParams, "prompt")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        if (prompt.Any(p => !KnownPrompts.Contains(p)))
            return Fail(OAuthError.InvalidRequest("unsupported prompt value"));
        if (prompt.Contains("none") && prompt.Count > 1)
            return Fail(OAuthError.InvalidRequest("prompt=none cannot be combined with other values"));

        int? maxAge = null;
        var maxAgeParam = GetParam(effectiveParams, "max_age");
        if (!string.IsNullOrEmpty(maxAgeParam))
        {
            if (!int.TryParse(maxAgeParam, out var parsedMaxAge) || parsedMaxAge < 0)
                return Fail(OAuthError.InvalidRequest("max_age must be a non-negative integer"));
            maxAge = parsedMaxAge;
        }

        string? hintSubject = null;
        var idTokenHint = GetParam(effectiveParams, "id_token_hint");
        if (!string.IsNullOrEmpty(idTokenHint))
        {
            var hint = await _tokenFactory.ValidateIdTokenHintAsync(idTokenHint, ct);
            hintSubject = hint?.FindFirst("sub")?.Value;
            if (hintSubject is null)
                return Fail(OAuthError.InvalidRequest("id_token_hint is invalid"));
        }

        if (!ClaimsEngine.TryParse(claimsParam, out var claimsRequest, out var claimsError))
            return Fail(OAuthError.InvalidRequest(claimsError));

        // ── Resource Indicators (RFC 8707) ────────────────────────────────────
        IReadOnlyList<string> resources = [];
        if (opts.ResourceIndicatorsEnabled)
        {
            resources = ResourceIndicators.Split(GetParam(effectiveParams, "resource"));
            if (ResourceIndicators.Validate(resources, opts, client) is { } targetError)
                return Fail(OAuthError.InvalidTarget(targetError));
        }

        // ── Rich Authorization Requests (RFC 9396) ────────────────────────────
        var (authDetailsJson, authDetailsError) = ParseAuthorizationDetails(
            GetParam(effectiveParams, "authorization_details"), opts);
        if (authDetailsError is not null)
            return Fail(OAuthError.InvalidAuthorizationDetails(authDetailsError));

        // ── Interaction (login + consent) ─────────────────────────────────────
        PendingInteraction? resumed = null;
        var interactionId = GetParam(raw, InteractionParameter);
        if (!string.IsNullOrEmpty(interactionId) &&
            await _interactions.FindAsync(interactionId, ct) is { } pending && pending.ClientId == client.ClientId)
            resumed = pending;

        // The End-User cancelled the login or denied consent (OIDC Core §3.1.2.6).
        if (resumed?.DenialError is { } denial)
        {
            await ConsumeParAsync(resolved, ct);
            await _interactions.RemoveAsync(resumed.InteractionId, ct);
            return Fail(new OAuthError(denial, resumed.DenialDescription));
        }

        var outcome = await _interactionService.EvaluateAsync(new InteractionRequest
        {
            HttpContext = context,
            Client = client,
            RequestedScopes = requestedScopes,
            Prompt = prompt,
            MaxAge = maxAge,
            IdTokenHintSubject = hintSubject,
            LoginHint = NullIfEmpty(GetParam(effectiveParams, "login_hint")),
            AcrValues = GetParam(effectiveParams, "acr_values").Split(' ', StringSplitOptions.RemoveEmptyEntries),
            UiLocales = NullIfEmpty(GetParam(effectiveParams, "ui_locales")),
            ResumedInteraction = resumed,
        }, ct);

        // id_token_hint names a different End-User than the one signed in (OIDC Core §3.1.2.1).
        if (outcome.Kind == InteractionOutcomeKind.Completed && hintSubject is not null &&
            _subjects.Compute(outcome.Subject!, client) != hintSubject)
            outcome = InteractionOutcome.Requires(InteractionOutcomeKind.LoginRequired);

        if (outcome.Kind != InteractionOutcomeKind.Completed)
        {
            if (prompt.Contains("none"))
            {
                await ConsumeParAsync(resolved, ct);
                return Fail(outcome.Kind switch
                {
                    InteractionOutcomeKind.LoginRequired => OAuthError.LoginRequired(),
                    InteractionOutcomeKind.ConsentRequired => OAuthError.ConsentRequired(),
                    InteractionOutcomeKind.AccountSelectionRequired => OAuthError.AccountSelectionRequired(),
                    _ => OAuthError.InteractionRequired(),
                });
            }
            return await SuspendForInteractionAsync(context, raw, client, requestedScopes, effectiveParams, outcome.Kind, ct);
        }

        // OIDC Core §5.5.1.1: an essential acr that was not achieved fails the request.
        if (claimsRequest?.IdToken.TryGetValue("acr", out var acrRequest) == true &&
            acrRequest.Essential && acrRequest.Values is { Length: > 0 } &&
            (outcome.Acr is null || !acrRequest.Values.Contains(outcome.Acr)))
            return Fail(OAuthError.AccessDenied("the requested authentication context was not achieved"));

        // The request is complete: spend the pushed request and the interaction.
        if (!await ConsumeParAsync(resolved, ct))
            return Fail(OAuthError.InvalidRequestUri("request_uri was already used"));
        if (resumed is not null)
            await _interactions.RemoveAsync(resumed.InteractionId, ct);

        var localSubject = outcome.Subject!;
        var grantedScopes = outcome.GrantedScopes;
        var authTime = outcome.AuthTime;

        // Create or update the OIDC session (no-op when LogoutEnabled is false).
        var session = await _sessionService.EnsureSessionAsync(context, localSubject, clientId, ct);
        var sid = session?.SessionId;

        var response = new Dictionary<string, string?>();
        if (!string.IsNullOrEmpty(state)) response["state"] = state;

        // RFC 9207: add iss to every authorization response
        if (opts.IssuerIdentificationEnabled)
            response["iss"] = opts.Issuer.TrimEnd('/');

        // ── Code: one grant per authorization, shared by every token it yields ─
        string? codeValue = null;
        string? grantId = null;
        if (includesCode)
        {
            var codeLifetime = TimeSpan.FromSeconds(opts.AuthorizationCodeLifetimeSeconds);
            grantId = await _grants.CreateAsync(clientId, localSubject, grantedScopes, codeLifetime, ct);
            codeValue = GenerateId();
            await _codeStore.StoreAsync(codeValue, new AuthorizationCode
            {
                Code = codeValue,
                ClientId = clientId,
                RedirectUri = redirectUri,
                RedirectUriInRequest = redirectUriInRequest,
                Subject = localSubject,
                Scopes = grantedScopes,
                Nonce = NullIfEmpty(nonce),
                CodeChallenge = NullIfEmpty(codeChallenge),
                CodeChallengeMethod = string.IsNullOrEmpty(codeChallenge) ? null : codeChallengeMethod,
                DPoPJkt = NullIfEmpty(GetParam(effectiveParams, "dpop_jkt")),
                AuthTime = authTime,
                ExpiresAt = DateTimeOffset.UtcNow + codeLifetime,
                ClaimsRequest = NullIfEmpty(claimsParam),
                Acr = outcome.Acr,
                Amr = outcome.Amr,
                SessionId = sid,
                Resources = resources,
                AuthorizationDetailsJson = authDetailsJson,
                GrantId = grantId,
            }, codeLifetime, ct);
            response["code"] = codeValue;
        }

        // ── Access token directly (implicit / hybrid with 'token') ────────────
        string? accessToken = null;
        if (includesToken)
        {
            var issued = await _issuer.IssueAsync(new TokenIssuanceRequest
            {
                Client = client,
                GrantType = "implicit",
                Subject = localSubject,
                Scopes = grantedScopes,
                Resources = resources,
                AuthorizationDetailsJson = authDetailsJson,
                GrantId = grantId,
                ClaimsRequest = NullIfEmpty(claimsParam),
            }, ct);
            accessToken = issued.AccessToken;
            response["access_token"] = issued.AccessToken;
            response["token_type"] = issued.TokenType;
            response["expires_in"] = issued.ExpiresIn.ToString();
        }

        // ── ID token directly (implicit / hybrid), with at_hash, c_hash and s_hash ──
        if (includesIdToken)
        {
            response["id_token"] = await _issuer.CreateIdTokenAsync(client, localSubject, grantedScopes,
                new IdTokenParameters(authTime, NullIfEmpty(nonce), outcome.Acr, outcome.Amr, sid,
                    NullIfEmpty(claimsParam), Code: codeValue,
                    // OIDC Core §5.4: without an access token the scope claims go in the ID token.
                    IncludeScopeClaims: !includesToken && !includesCode,
                    // FAPI 1.0 Advanced §5.2.2.1: s_hash protects state in front-channel ID tokens.
                    State: NullIfEmpty(state)),
                accessToken, ct);
        }

        await _events.AuthorizationSucceededAsync(new AuthorizationSucceededEvent(
            clientId, localSubject, rawResponseType, grantedScopes, authTime), ct);

        return BuildRedirect(redirectUri, baseMode, response, useJarm ? client : null);
    }

    // ── Parameter sources ─────────────────────────────────────────────────────

    /// <summary>
    /// Reads query (GET) or form (POST) parameters. Repeated <c>resource</c> values are joined
    /// with spaces; other repeated parameters are an error per RFC 6749 §3.1 and keep the first.
    /// </summary>
    private static async Task<Dictionary<string, string>> ReadRawParametersAsync(HttpContext context, CancellationToken ct)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync(ct);
            foreach (var key in form.Keys)
                result[key] = key == "resource" ? string.Join(' ', form[key].ToArray()) : form[key].ToString();
        }
        else
        {
            foreach (var key in context.Request.Query.Keys)
            {
                var values = context.Request.Query[key];
                result[key] = key == "resource" ? string.Join(' ', values.ToArray()) : values[0] ?? string.Empty;
            }
        }
        return result;
    }

    private sealed record ResolvedParameters(
        IReadOnlyDictionary<string, string> Params,
        OAuthError? Error,
        bool FromPar = false,
        bool FromRequestObject = false,
        string? ParRequestUri = null);

    private async Task<ResolvedParameters> ResolveParametersAsync(
        IReadOnlyDictionary<string, string> raw, Client client, ProviderOptions opts, CancellationToken ct)
    {
        var requestUri = GetParam(raw, "request_uri");
        var requestJwt = GetParam(raw, "request");
        var requireRequestObject = client.RequireSignedRequestObject || opts.JarRequireSignedRequestObject;

        // ── request_uri by reference (RFC 9101 §5.2): fetch, then treat as a request parameter ──
        if (!string.IsNullOrEmpty(requestUri) &&
            !requestUri.StartsWith("urn:ietf:params:oauth:request_uri:", StringComparison.Ordinal) &&
            opts.JarEnabled && opts.RequestUriParameterSupported)
        {
            if (!string.IsNullOrEmpty(requestJwt))
                return new(raw, OAuthError.InvalidRequest("request and request_uri must not both be present"));
            var (fetched, fetchError) = await _requestObjectValidator.FetchAsync(requestUri, client, ct);
            if (fetchError is not null)
                return new(raw, OAuthError.InvalidRequestUri(fetchError));
            requestJwt = fetched!;
            requestUri = string.Empty;
        }

        // ── PAR: request_uri ───────────────────────────────────────────────────
        if (!string.IsNullOrEmpty(requestUri))
        {
            // request_uri by reference is only fetched when RequestUriParameterSupported (above).
            if (!requestUri.StartsWith("urn:ietf:params:oauth:request_uri:", StringComparison.Ordinal))
                return new(raw, OAuthError.RequestUriNotSupported(
                    "only request_uri values from the pushed authorization endpoint are supported"));

            // Peek only: the request is spent when the authorization completes, so a login
            // redirect in between can resume it.
            var par = await _parStore.FindAsync(requestUri, ct);
            if (par is null || par.ExpiresAt < DateTimeOffset.UtcNow)
                return new(raw, OAuthError.InvalidRequestUri("request_uri not found, expired, or already used"));
            if (par.ClientId != client.ClientId)
                return new(raw, OAuthError.InvalidRequestUri("request_uri belongs to a different client"));
            if (requireRequestObject && !par.FromRequestObject)
                return new(raw, OAuthError.InvalidRequest("a signed request object is required"));

            var stored = JsonSerializer.Deserialize<Dictionary<string, string>>(par.ParametersJson);
            if (stored is null)
                return new(raw, OAuthError.InvalidRequestUri("could not deserialize pushed authorization request"));

            return new(stored, null, FromPar: true, FromRequestObject: par.FromRequestObject, ParRequestUri: requestUri);
        }

        if (opts.RequirePushedAuthorization)
            return new(raw, OAuthError.InvalidRequest("request_uri is required (pushed authorization is mandatory)"));

        // ── JAR: request JWT ───────────────────────────────────────────────────
        if (!string.IsNullOrEmpty(requestJwt))
        {
            if (!opts.JarEnabled)
                return new(raw, OAuthError.RequestNotSupported("request parameter is not supported (JAR is disabled)"));

            var (claims, error) = await _requestObjectValidator.ValidateAsync(
                requestJwt, client, opts.Issuer.TrimEnd('/'), ct);
            if (error is not null)
                return new(raw, OAuthError.InvalidRequestObject(error));

            // RFC 9101 §6.3: only the request object's parameters are used.
            var effective = RequestObjectValidator.ToAuthorizationParameters(claims!);
            if (effective.TryGetValue("client_id", out var jwtClientId) && jwtClientId != client.ClientId)
                return new(raw, OAuthError.InvalidRequestObject("client_id in request object does not match query client_id"));
            effective["client_id"] = client.ClientId;

            return new(effective, null, FromRequestObject: true);
        }

        if (requireRequestObject)
            return new(raw, OAuthError.InvalidRequest("a signed request object is required"));

        return new(raw, null);
    }

    /// <summary>Spends the pushed request, if any. Returns false when it was already used.</summary>
    private async Task<bool> ConsumeParAsync(ResolvedParameters resolved, CancellationToken ct) =>
        resolved.ParRequestUri is null || await _parStore.ConsumeAsync(resolved.ParRequestUri, ct) is not null;

    // ── Interaction redirects ─────────────────────────────────────────────────

    private async Task<IResult> SuspendForInteractionAsync(
        HttpContext context, IReadOnlyDictionary<string, string> raw, Client client,
        IReadOnlyList<string> scopes, IReadOnlyDictionary<string, string> effective,
        InteractionOutcomeKind kind, CancellationToken ct)
    {
        var opts = _options.Value;
        var kindToRecord = kind == InteractionOutcomeKind.ConsentRequired ? InteractionKind.Consent : InteractionKind.Login;
        var interactionId = GenerateId();
        await _interactions.StoreAsync(interactionId, new PendingInteraction
        {
            InteractionId = interactionId,
            ClientId = client.ClientId,
            Kind = kindToRecord,
        }, TimeSpan.FromSeconds(opts.InteractionLifetimeSeconds), ct);

        // Resume via GET with the original (outer) parameters plus the interaction id.
        var resumeParams = raw.Where(kv => kv.Key != InteractionParameter)
            .ToDictionary(kv => kv.Key, kv => (string?)kv.Value);
        resumeParams[InteractionParameter] = interactionId;
        var returnUrl = QueryHelpers.AddQueryString(context.Request.PathBase + context.Request.Path, resumeParams);

        if (kindToRecord == InteractionKind.Consent)
        {
            return Results.Redirect(QueryHelpers.AddQueryString(opts.ConsentPath, new Dictionary<string, string?>
            {
                ["returnUrl"] = returnUrl,
                ["client_id"] = client.ClientId,
                ["scope"] = string.Join(' ', scopes),
            }));
        }

        var loginParams = new Dictionary<string, string?> { ["returnUrl"] = returnUrl };
        foreach (var hint in new[] { "login_hint", "ui_locales", "acr_values" })
            if (!string.IsNullOrEmpty(GetParam(effective, hint)))
                loginParams[hint] = GetParam(effective, hint);
        return Results.Redirect(QueryHelpers.AddQueryString(opts.LoginPath, loginParams));
    }

    // ── Response mode helpers (JARM) ───────────────────────────────────────────

    private static (string? BaseMode, bool UseJarm) ParseResponseMode(
        string responseMode, bool isCode, ProviderOptions opts)
    {
        if (string.IsNullOrEmpty(responseMode))
            responseMode = isCode ? "query" : "fragment";

        if (responseMode == "jwt" || responseMode.EndsWith(".jwt", StringComparison.Ordinal))
        {
            if (!opts.JarmEnabled) return (null, false);

            var prefix = responseMode == "jwt" ? "" : responseMode[..^4];
            var baseMode = prefix switch
            {
                "" => isCode ? "query" : "fragment",
                "query" => "query",
                "fragment" => "fragment",
                "form_post" => "form_post",
                _ => null,
            };
            return (baseMode, true);
        }

        return responseMode is "query" or "fragment" or "form_post"
            ? (responseMode, false)
            : (null, false);
    }

    // ── Rich Authorization Requests (RFC 9396) ─────────────────────────────────

    private static (string? Json, string? Error) ParseAuthorizationDetails(
        string authDetailsParam, ProviderOptions opts)
    {
        // OID4VCI wallets use authorization_details even when general RAR support is off.
        if ((!opts.RichAuthorizationRequestsEnabled && !opts.VciEnabled) || string.IsNullOrEmpty(authDetailsParam))
            return (null, null);

        System.Text.Json.Nodes.JsonArray details;
        try
        {
            if (System.Text.Json.Nodes.JsonNode.Parse(authDetailsParam) is not System.Text.Json.Nodes.JsonArray array)
                return (null, "authorization_details must be a JSON array");
            details = array;
        }
        catch (JsonException)
        {
            return (null, "authorization_details is not valid JSON");
        }

        foreach (var entry in details)
        {
            if (entry is not System.Text.Json.Nodes.JsonObject obj || NetOidc.Provider.Http.JsonNodeExtensions.AsString(obj["type"]) is not { Length: > 0 } type)
                return (null, "each authorization_details entry must be an object with a type");
            if (!opts.RichAuthorizationRequestsEnabled && type != Vci.CredentialAuthorizationDetails.Type)
                return (null, $"authorization_details type '{type}' is not supported");
        }

        if (Vci.CredentialAuthorizationDetails.ValidateAndEnrich(details, opts) is { } error)
            return (null, error);
        return (details.ToJsonString(), null);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static string GetParam(IReadOnlyDictionary<string, string> d, string key) =>
        d.TryGetValue(key, out var v) ? v : string.Empty;

    private static string? NullIfEmpty(string value) => string.IsNullOrEmpty(value) ? null : value;

    /// <summary>
    /// Sorts the space-separated response_type tokens alphabetically so that
    /// "token id_token" and "id_token token" compare equal.
    /// </summary>
    internal static string NormalizeResponseType(string raw) =>
        string.Join(" ", raw.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                             .OrderBy(t => t, StringComparer.Ordinal));

    /// <summary>
    /// Validates the redirect_uri. For loopback addresses (RFC 8252 §7.3), port differences
    /// are ignored when <see cref="ProviderOptions.AllowNativeAppRedirects"/> is enabled.
    /// </summary>
    private bool IsValidRedirectUri(Client client, string requestedUri)
    {
        if (client.RedirectUris.Contains(requestedUri)) return true;

        if (_options.Value.AllowNativeAppRedirects && IsLoopbackUri(requestedUri))
        {
            var reqBase = GetLoopbackBase(requestedUri);
            return client.RedirectUris.Any(r => IsLoopbackUri(r) && GetLoopbackBase(r) == reqBase);
        }

        return false;
    }

    private static bool IsLoopbackUri(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed)) return false;
        return parsed.Scheme == "http" &&
               (parsed.Host == "localhost" || parsed.Host == "127.0.0.1" || parsed.Host == "[::1]");
    }

    private static string GetLoopbackBase(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed)) return uri;
        return $"{parsed.Scheme}://{parsed.Host}{parsed.AbsolutePath}".TrimEnd('/');
    }

    private static IResult ShowErrorPage(string message) =>
        Results.BadRequest(OAuthError.InvalidRequest(message));

    /// <summary>
    /// For a request whose request object could not be used (unsupported, unverifiable): adds the
    /// object's <c>response_mode</c>, <c>response_type</c> and <c>state</c> — read without
    /// verification — when the outer request lacks them. They only decide how the error reaches
    /// the already-validated redirect URI, so the client gets it where it expects it.
    /// </summary>
    private static IReadOnlyDictionary<string, string> WithRequestObjectHints(IReadOnlyDictionary<string, string> parameters)
    {
        var requestObject = GetParam(parameters, "request");
        if (string.IsNullOrEmpty(requestObject) || requestObject.Count(c => c == '.') != 2)
            return parameters;
        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(requestObject.Split('.')[1]));
            var merged = new Dictionary<string, string>(parameters, StringComparer.Ordinal);
            foreach (var name in new[] { "response_mode", "response_type", "state" })
                if (!merged.ContainsKey(name) &&
                    payload.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
                    merged[name] = value.GetString()!;
            return merged;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException or InvalidOperationException)
        {
            return parameters;
        }
    }

    /// <summary>
    /// How to return an error found before the response mode is settled: the requested
    /// <c>response_mode</c> when it is a plain mode (or the base of a JARM mode), otherwise the
    /// default for the <c>response_type</c> — fragment whenever tokens would be returned
    /// (OAuth 2.0 Multiple Response Types §5), query for <c>code</c>.
    /// </summary>
    private static string? ErrorResponseMode(IReadOnlyDictionary<string, string> parameters)
    {
        var mode = GetParam(parameters, "response_mode");
        if (mode.EndsWith(".jwt", StringComparison.Ordinal))
            mode = mode[..^4];
        if (mode is "query" or "fragment" or "form_post")
            return mode;
        return NormalizeResponseType(GetParam(parameters, "response_type")) is "" or "code" or "none"
            ? null
            : "fragment";
    }

    /// <summary>
    /// Returns an authorization error to the client's redirect URI (RFC 6749 §4.1.2.1) with
    /// <c>iss</c> when issuer identification is on (RFC 9207 §2), JARM-wrapped when
    /// <paramref name="jarmClient"/> is set (JARM §2.3: errors are signed like any response).
    /// </summary>
    private IResult SendError(
        string redirectUri, string? state, string? responseMode, OAuthError error, Client? jarmClient = null)
    {
        var p = new Dictionary<string, string?> { ["error"] = error.Error, ["error_description"] = error.Description };
        if (!string.IsNullOrEmpty(state)) p["state"] = state;
        if (_options.Value.IssuerIdentificationEnabled) p["iss"] = _options.Value.Issuer.TrimEnd('/');
        return BuildRedirect(redirectUri, responseMode, p, jarmClient);
    }

    /// <summary>JARM applies to an early error when the request asked for a <c>jwt</c> response mode.</summary>
    private Client? ErrorJarmClient(IReadOnlyDictionary<string, string> parameters, Client client)
    {
        var mode = GetParam(parameters, "response_mode");
        return _options.Value.JarmEnabled && (mode == "jwt" || mode.EndsWith(".jwt", StringComparison.Ordinal))
            ? client
            : null;
    }

    private IResult BuildRedirect(
        string redirectUri, string? responseMode,
        IDictionary<string, string?> parameters, Client? jarmClient)
    {
        var nonNull = parameters
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!);

        if (jarmClient is not null)
        {
            var jarmJwt = _tokenFactory.CreateJarmToken(jarmClient.ClientId, nonNull, jarmClient.AuthorizationSignedResponseAlg);
            nonNull = new Dictionary<string, string> { ["response"] = jarmJwt };
        }

        return responseMode switch
        {
            "fragment" => Results.Redirect(BuildFragmentUri(redirectUri, nonNull)),
            "form_post" => Results.Content(BuildFormPostHtml(redirectUri, nonNull), "text/html"),
            _ => Results.Redirect(QueryHelpers.AddQueryString(redirectUri,
                    nonNull.ToDictionary(kv => kv.Key, kv => (string?)kv.Value))),
        };
    }

    private static string BuildFragmentUri(string baseUri, IDictionary<string, string> p)
    {
        var fragment = string.Join("&", p.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return baseUri.Split('#')[0] + '#' + fragment;
    }

    private static string BuildFormPostHtml(string redirectUri, IDictionary<string, string> p)
    {
        var enc = HtmlEncoder.Default;
        var inputs = string.Concat(p.Select(kv =>
            $"""<input type="hidden" name="{enc.Encode(kv.Key)}" value="{enc.Encode(kv.Value)}" />"""));

        return $"""
            <!DOCTYPE html>
            <html>
              <head><title>Redirecting…</title></head>
              <body onload="document.forms[0].submit()">
                <form method="post" action="{enc.Encode(redirectUri)}">
                  {inputs}
                  <noscript><button type="submit">Continue</button></noscript>
                </form>
              </body>
            </html>
            """;
    }

    private static string GenerateId() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
