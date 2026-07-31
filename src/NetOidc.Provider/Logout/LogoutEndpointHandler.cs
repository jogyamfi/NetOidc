using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Session;

namespace NetOidc.Provider.Logout;

/// <summary>
/// Handles RP-Initiated Logout (OIDC Session Management §5 /
/// OpenID Connect RP-Initiated Logout 1.0) on
/// <c>GET|POST /connect/end_session</c>.
///
/// Flow:
/// 1. Parse <c>id_token_hint</c>, <c>post_logout_redirect_uri</c>, <c>state</c>.
/// 2. Optionally validate <c>post_logout_redirect_uri</c> against the client's registered URIs.
/// 3. Sign the user out of the ASP.NET Core cookie session.
/// 4. Remove the OIDC session and optionally trigger back-channel logout.
/// 5. Redirect to <c>post_logout_redirect_uri</c> (with <c>state</c>) or return 204.
/// </summary>
public sealed class LogoutEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly TokenFactory _tokenFactory;
    private readonly SessionService _sessionService;
    private readonly BackChannelLogoutService? _backChannelLogout;

    public LogoutEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        TokenFactory tokenFactory,
        SessionService sessionService,
        BackChannelLogoutService? backChannelLogout = null)
    {
        _options = options;
        _clientStore = clientStore;
        _tokenFactory = tokenFactory;
        _sessionService = sessionService;
        _backChannelLogout = backChannelLogout;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        string? idTokenHint, postLogoutRedirectUri, state, clientId;

        if (context.Request.Method == HttpMethods.Post && context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync(ct);
            idTokenHint = form["id_token_hint"];
            postLogoutRedirectUri = form["post_logout_redirect_uri"];
            state = form["state"];
            clientId = form["client_id"];
        }
        else
        {
            var q = context.Request.Query;
            idTokenHint = q["id_token_hint"];
            postLogoutRedirectUri = q["post_logout_redirect_uri"];
            state = q["state"];
            clientId = q["client_id"];
        }

        // Validate post_logout_redirect_uri if provided.
        string? resolvedClientId = clientId;
        string? sessionId = null;

        if (!string.IsNullOrEmpty(idTokenHint))
        {
            var principal = await _tokenFactory.ValidateIdTokenHintAsync(idTokenHint, ct);
            if (principal is not null)
            {
                resolvedClientId ??= principal.FindFirst("aud")?.Value
                    ?? principal.FindFirst("azp")?.Value;
                sessionId = principal.FindFirst("sid")?.Value;
            }
        }

        if (!string.IsNullOrEmpty(postLogoutRedirectUri) && !string.IsNullOrEmpty(resolvedClientId))
        {
            var client = await _clientStore.FindClientAsync(resolvedClientId, ct);
            if (client is not null && client.PostLogoutRedirectUris.Count > 0
                && !client.PostLogoutRedirectUris.Contains(postLogoutRedirectUri))
            {
                return Results.BadRequest(OAuthError.InvalidRequest(
                    "post_logout_redirect_uri not registered for this client"));
            }
        }

        // Remove OIDC session and trigger back-channel logout.
        if (sessionId is not null)
        {
            var session = await _sessionService.GetSessionAsync(sessionId, ct);
            if (session is not null)
            {
                if (_backChannelLogout is not null && opts.BackChannelLogoutEnabled)
                    await _backChannelLogout.NotifyAsync(session, opts.LogoutTokenLifetimeSeconds, ct);

                await _sessionService.RemoveSessionAsync(sessionId, ct);
            }
        }

        // Sign out of the ASP.NET Core cookie scheme.
        await context.SignOutAsync();

        // Clear the OIDC session cookie.
        context.Response.Cookies.Delete(SessionService.CookieName);

        if (!string.IsNullOrEmpty(postLogoutRedirectUri))
        {
            var target = string.IsNullOrEmpty(state)
                ? postLogoutRedirectUri
                : $"{postLogoutRedirectUri}?state={Uri.EscapeDataString(state)}";
            return Results.Redirect(target);
        }

        return Results.NoContent();
    }
}
