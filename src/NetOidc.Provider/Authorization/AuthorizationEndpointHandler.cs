using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Interaction;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Authorization;

/// <summary>
/// Handles GET/POST requests to the authorization endpoint.
/// Supports authorization_code, implicit, and hybrid flows per OIDC Core §3.
/// </summary>
public sealed class AuthorizationEndpointHandler
{
    // Normalized response_type sets (space-separated tokens, sorted alphabetically)
    private static readonly HashSet<string> CodeResponseTypes = ["code"];
    private static readonly HashSet<string> ImplicitResponseTypes = ["id_token", "id_token token", "token"];
    private static readonly HashSet<string> HybridResponseTypes =
        ["code id_token", "code id_token token", "code token"];

    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly IAdapter<AuthorizationCode> _codeStore;
    private readonly IInteractionService _interactionService;
    private readonly TokenFactory _tokenFactory;
    private readonly SubjectIdentifierService _subjectIdentifier;
    private readonly IAdapter<AccessToken> _accessTokenStore;

    public AuthorizationEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        IAdapter<AuthorizationCode> codeStore,
        IInteractionService interactionService,
        TokenFactory tokenFactory,
        SubjectIdentifierService subjectIdentifier,
        IAdapter<AccessToken> accessTokenStore)
    {
        _options = options;
        _clientStore = clientStore;
        _codeStore = codeStore;
        _interactionService = interactionService;
        _tokenFactory = tokenFactory;
        _subjectIdentifier = subjectIdentifier;
        _accessTokenStore = accessTokenStore;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var q = context.Request.Query;

        var clientId = q["client_id"].ToString();
        var redirectUri = q["redirect_uri"].ToString();

        // client_id and redirect_uri must be validated before any error redirect
        if (string.IsNullOrEmpty(clientId))
            return ShowErrorPage("client_id is required");

        var client = await _clientStore.FindClientAsync(clientId, ct);
        if (client is null)
            return ShowErrorPage("unknown client_id");

        if (string.IsNullOrEmpty(redirectUri))
        {
            if (client.RedirectUris.Count == 1)
                redirectUri = client.RedirectUris[0];
            else
                return ShowErrorPage("redirect_uri is required");
        }

        if (!IsValidRedirectUri(client, redirectUri))
            return ShowErrorPage("redirect_uri not registered for this client");

        // Parse remaining parameters
        var rawResponseType = q["response_type"].ToString();
        var scope = q["scope"].ToString();
        var state = q["state"].ToString();
        var nonce = q["nonce"].ToString();
        var responseMode = q["response_mode"].ToString();
        var codeChallenge = q["code_challenge"].ToString();
        var codeChallengeMethod = q["code_challenge_method"].ToString();
        var claimsParam = q["claims"].ToString();

        // Normalize response_type (sort tokens so comparisons are order-independent)
        var normalizedResponseType = NormalizeResponseType(rawResponseType);

        var isCode = CodeResponseTypes.Contains(normalizedResponseType);
        var isImplicit = ImplicitResponseTypes.Contains(normalizedResponseType);
        var isHybrid = HybridResponseTypes.Contains(normalizedResponseType);

        if (!isCode && !isImplicit && !isHybrid)
            return SendError(redirectUri, state, null,
                OAuthError.UnsupportedResponseType($"Unsupported response_type: {rawResponseType}"));

        var requiredGrant = isCode ? "authorization_code" : isHybrid ? "hybrid" : "implicit";
        if (!client.AllowedGrantTypes.Contains(requiredGrant))
            return SendError(redirectUri, state, null, OAuthError.UnauthorizedClient());

        // Default response_mode per flow type
        if (string.IsNullOrEmpty(responseMode))
            responseMode = isCode ? "query" : "fragment";

        if (responseMode is not ("query" or "fragment" or "form_post"))
            return SendError(redirectUri, state, responseMode,
                OAuthError.InvalidRequest($"Unsupported response_mode: {responseMode}"));

        // query mode must not be used when tokens are returned directly (security)
        if (responseMode == "query" && (isImplicit || isHybrid))
            return SendError(redirectUri, state, responseMode,
                OAuthError.InvalidRequest("response_mode=query is not permitted for implicit/hybrid flows"));

        // Parse and validate scopes
        var requestedScopes = string.IsNullOrEmpty(scope)
            ? new List<string>()
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        var registeredScopes = _options.Value.Scopes.Select(s => s.Name).ToHashSet();
        var unknownScopes = requestedScopes.Where(s => !registeredScopes.Contains(s)).ToList();
        if (unknownScopes.Count > 0)
            return SendError(redirectUri, state, responseMode,
                OAuthError.InvalidScope($"Unknown scope(s): {string.Join(" ", unknownScopes)}"));

        var disallowedScopes = requestedScopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
        if (disallowedScopes.Count > 0)
            return SendError(redirectUri, state, responseMode,
                OAuthError.InvalidScope($"Client not authorized for: {string.Join(" ", disallowedScopes)}"));

        // nonce is required when an id_token is issued directly (OIDC Core §3.2.2.1, §3.3.2.11)
        var includesIdToken = normalizedResponseType.Contains("id_token");
        if (includesIdToken && !isCode && string.IsNullOrEmpty(nonce))
            return SendError(redirectUri, state, responseMode,
                OAuthError.InvalidRequest("nonce is required when response_type includes id_token"));

        // PKCE validation applies to all flows that return a code
        var includesCode = normalizedResponseType.Contains("code");
        if (includesCode)
        {
            if (client.RequirePkce && string.IsNullOrEmpty(codeChallenge))
                return SendError(redirectUri, state, responseMode,
                    OAuthError.InvalidRequest("code_challenge is required (PKCE)"));

            if (!string.IsNullOrEmpty(codeChallenge))
            {
                if (string.IsNullOrEmpty(codeChallengeMethod))
                    codeChallengeMethod = "plain";
                if (!codeChallengeMethod.Equals("S256", StringComparison.OrdinalIgnoreCase) &&
                    !codeChallengeMethod.Equals("plain", StringComparison.OrdinalIgnoreCase))
                    return SendError(redirectUri, state, responseMode,
                        OAuthError.InvalidRequest("Unsupported code_challenge_method; use S256 or plain"));
            }
        }

        // Check interaction (login + consent)
        var interaction = await _interactionService.GetInteractionResultAsync(
            context, clientId, requestedScopes, ct);

        if (interaction is null)
        {
            var returnUrl = Uri.EscapeDataString(
                context.Request.Path + context.Request.QueryString);
            return Results.Redirect($"{_options.Value.LoginPath}?returnUrl={returnUrl}");
        }

        // Compute effective subject (public or pairwise per OIDC Core §8)
        var effectiveSub = _subjectIdentifier.Compute(interaction.Subject, clientId);
        var grantedScopes = interaction.GrantedScopes;
        var authTime = DateTimeOffset.UtcNow;

        var response = new Dictionary<string, string?>();
        if (!string.IsNullOrEmpty(state)) response["state"] = state;

        // RFC 9207: add iss to every authorization response
        if (_options.Value.IssuerIdentificationEnabled)
            response["iss"] = _options.Value.Issuer.TrimEnd('/');

        // Issue code for code/hybrid flows
        if (includesCode)
        {
            var opts = _options.Value;
            var codeValue = GenerateId();
            var authCode = new AuthorizationCode
            {
                Code = codeValue,
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = effectiveSub,
                Scopes = grantedScopes,
                Nonce = string.IsNullOrEmpty(nonce) ? null : nonce,
                CodeChallenge = string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
                CodeChallengeMethod = string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod,
                AuthTime = authTime,
                ExpiresAt = authTime.Add(TimeSpan.FromSeconds(opts.AuthorizationCodeLifetimeSeconds)),
                ClaimsRequest = string.IsNullOrEmpty(claimsParam) ? null : claimsParam,
                Acr = interaction.Acr,
                Amr = interaction.Amr,
            };
            await _codeStore.StoreAsync(codeValue, authCode,
                TimeSpan.FromSeconds(opts.AuthorizationCodeLifetimeSeconds), ct);
            response["code"] = codeValue;
        }

        // Issue access token for flows where 'token' is a response_type token (implicit/hybrid)
        var includesToken = normalizedResponseType.Contains("token") && !isCode;
        if (includesToken)
        {
            var opts = _options.Value;
            var tokenId = GenerateId();
            var atValue = _tokenFactory.CreateAccessToken(tokenId, effectiveSub, clientId, grantedScopes);
            var at = new AccessToken
            {
                TokenId = tokenId,
                GrantId = tokenId,
                ClientId = clientId,
                Subject = effectiveSub,
                Scopes = grantedScopes,
                ExpiresAt = authTime.AddSeconds(opts.AccessTokenLifetimeSeconds),
            };
            await _accessTokenStore.StoreAsync(tokenId, at,
                TimeSpan.FromSeconds(opts.AccessTokenLifetimeSeconds), ct);
            response["access_token"] = atValue;
            response["token_type"] = "Bearer";
            response["expires_in"] = opts.AccessTokenLifetimeSeconds.ToString();
        }

        // Issue id_token directly for implicit/hybrid flows (not for pure code flow)
        if (includesIdToken && !isCode)
        {
            var idToken = _tokenFactory.CreateIdToken(
                effectiveSub, clientId,
                nonce: string.IsNullOrEmpty(nonce) ? null : nonce,
                authTime: authTime,
                acr: interaction.Acr,
                amr: interaction.Amr);
            response["id_token"] = idToken;
        }

        return BuildRedirect(redirectUri, responseMode, response);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sorts the space-separated response_type tokens alphabetically so that
    /// "token id_token" and "id_token token" compare equal.
    /// </summary>
    private static string NormalizeResponseType(string raw) =>
        string.Join(" ", raw.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                             .Select(t => t.Trim())
                             .Where(t => t.Length > 0)
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

    private static IResult SendError(
        string redirectUri, string? state, string? responseMode, OAuthError error)
    {
        var p = new Dictionary<string, string?> { ["error"] = error.Error };
        if (error.Description is not null) p["error_description"] = error.Description;
        if (!string.IsNullOrEmpty(state)) p["state"] = state;
        return BuildRedirect(redirectUri, responseMode, p);
    }

    private static IResult BuildRedirect(
        string redirectUri, string? responseMode, IDictionary<string, string?> parameters)
    {
        var nonNull = parameters
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!);

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

