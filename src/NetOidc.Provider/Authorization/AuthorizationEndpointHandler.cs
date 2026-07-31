using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Interaction;

namespace NetOidc.Provider.Authorization;

/// <summary>Handles GET/POST requests to the authorization endpoint.</summary>
public sealed class AuthorizationEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly IAdapter<AuthorizationCode> _codeStore;
    private readonly IInteractionService _interactionService;

    public AuthorizationEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        IAdapter<AuthorizationCode> codeStore,
        IInteractionService interactionService)
    {
        _options = options;
        _clientStore = clientStore;
        _codeStore = codeStore;
        _interactionService = interactionService;
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

        if (!client.RedirectUris.Contains(redirectUri))
            return ShowErrorPage("redirect_uri not registered for this client");

        // Parse remaining parameters
        var responseType = q["response_type"].ToString();
        var scope = q["scope"].ToString();
        var state = q["state"].ToString();
        var nonce = q["nonce"].ToString();
        var responseMode = q["response_mode"].ToString();
        var codeChallenge = q["code_challenge"].ToString();
        var codeChallengeMethod = q["code_challenge_method"].ToString();

        // Validate response_type
        if (responseType != "code")
            return SendError(redirectUri, state, responseMode,
                OAuthError.UnsupportedResponseType("Only 'code' is supported"));

        // Validate client is allowed to use authorization_code
        if (!client.AllowedGrantTypes.Contains("authorization_code"))
            return SendError(redirectUri, state, responseMode,
                OAuthError.UnauthorizedClient());

        // Parse and validate scopes
        var requestedScopes = string.IsNullOrEmpty(scope)
            ? []
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

        // Validate PKCE
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

        // Check interaction (login + consent)
        var interaction = await _interactionService.GetInteractionResultAsync(
            context, clientId, requestedScopes, ct);

        if (interaction is null)
        {
            var returnUrl = Uri.EscapeDataString(
                context.Request.Path + context.Request.QueryString);
            return Results.Redirect($"{_options.Value.LoginPath}?returnUrl={returnUrl}");
        }

        // Issue authorization code
        var opts = _options.Value;
        var codeValue = GenerateCode();
        var authCode = new AuthorizationCode
        {
            Code = codeValue,
            ClientId = clientId,
            RedirectUri = redirectUri,
            Subject = interaction.Subject,
            Scopes = interaction.GrantedScopes,
            Nonce = string.IsNullOrEmpty(nonce) ? null : nonce,
            CodeChallenge = string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
            CodeChallengeMethod = string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod,
            AuthTime = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.AuthorizationCodeLifetimeSeconds),
        };

        await _codeStore.StoreAsync(codeValue, authCode,
            TimeSpan.FromSeconds(opts.AuthorizationCodeLifetimeSeconds), ct);

        var successParams = new Dictionary<string, string?> { ["code"] = codeValue };
        if (!string.IsNullOrEmpty(state)) successParams["state"] = state;
        return BuildRedirect(redirectUri, responseMode, successParams);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

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
                    (IDictionary<string, string?>)nonNull.ToDictionary(kv => kv.Key, kv => (string?)kv.Value))),
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

    private static string GenerateCode() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
