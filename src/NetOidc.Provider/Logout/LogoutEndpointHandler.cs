using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Session;
using OidcSession = NetOidc.Provider.Abstractions.Models.Session;

namespace NetOidc.Provider.Logout;

/// <summary>
/// Handles RP-Initiated Logout 1.0 on <c>GET|POST /connect/end_session</c>.
/// <list type="number">
///   <item>Validate <c>id_token_hint</c>, <c>client_id</c> and <c>post_logout_redirect_uri</c>.</item>
///   <item>Without a valid hint, ask the End-User to confirm (redirect to
///   <see cref="ProviderOptions.LogoutConfirmationPath"/>); the confirmation is a POST with
///   <c>confirm=true</c> and an antiforgery token.</item>
///   <item>End the session: sign out, remove the OIDC session, notify clients over the back
///   channel and, when enabled, the front channel.</item>
///   <item>Redirect to <c>post_logout_redirect_uri</c> (with <c>state</c>) or return 204.</item>
/// </list>
/// </summary>
public sealed class LogoutEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly TokenFactory _tokenFactory;
    private readonly SessionService _sessionService;
    private readonly IAntiforgery _antiforgery;
    private readonly BackChannelLogoutService? _backChannelLogout;
    private readonly IProviderEventSink _events;
    private readonly Microsoft.Extensions.Logging.ILogger<LogoutEndpointHandler> _logger;

    public LogoutEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        TokenFactory tokenFactory,
        SessionService sessionService,
        IAntiforgery antiforgery,
        IProviderEventSink events,
        Microsoft.Extensions.Logging.ILogger<LogoutEndpointHandler> logger,
        BackChannelLogoutService? backChannelLogout = null)
    {
        _events = events;
        _logger = logger;
        _options = options;
        _clientStore = clientStore;
        _tokenFactory = tokenFactory;
        _sessionService = sessionService;
        _antiforgery = antiforgery;
        _backChannelLogout = backChannelLogout;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;
        var isPost = HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType;
        var source = isPost
            ? (await context.Request.ReadFormAsync(ct)).ToDictionary(kv => kv.Key, kv => kv.Value.ToString())
            : context.Request.Query.ToDictionary(kv => kv.Key, kv => kv.Value.ToString());

        string Param(string name) => source.TryGetValue(name, out var v) ? v : string.Empty;
        var idTokenHint = Param("id_token_hint");
        var postLogoutRedirectUri = Param("post_logout_redirect_uri");
        var state = Param("state");
        var clientId = NullIfEmpty(Param("client_id"));

        // ── id_token_hint ────────────────────────────────────────────────────
        string? hintSessionId = null;
        var hintValid = false;
        if (!string.IsNullOrEmpty(idTokenHint))
        {
            // An unverifiable hint (e.g. signed with a retired key) is treated as absent:
            // it cannot authorise a redirect or skip confirmation.
            var principal = await _tokenFactory.ValidateIdTokenHintAsync(idTokenHint, ct);
            if (principal is not null)
            {
                var hintClientId = principal.FindFirst("azp")?.Value ?? principal.FindFirst("aud")?.Value;

                // RP-Initiated Logout §2: client_id, when present, must match the hint's audience.
                if (clientId is not null && hintClientId is not null &&
                    !principal.FindAll("aud").Any(a => a.Value == clientId))
                    return Results.BadRequest(OAuthError.InvalidRequest(
                        "client_id does not match the id_token_hint audience"));

                clientId ??= hintClientId;
                hintSessionId = principal.FindFirst("sid")?.Value;
                hintValid = true;
            }
        }

        // ── post_logout_redirect_uri: only exact matches for an identified client ─
        if (!string.IsNullOrEmpty(postLogoutRedirectUri))
        {
            if (clientId is null)
                return Results.BadRequest(OAuthError.InvalidRequest(
                    "client_id or id_token_hint is required with post_logout_redirect_uri"));

            var client = await _clientStore.FindClientAsync(clientId, ct);
            if (client is null || !client.PostLogoutRedirectUris.Contains(postLogoutRedirectUri))
                return Results.BadRequest(OAuthError.InvalidRequest(
                    "post_logout_redirect_uri not registered for this client"));
        }

        // ── Confirmation (RP-Initiated Logout §2) ─────────────────────────────
        if (!hintValid)
        {
            var confirmed = isPost && Param("confirm") == "true";
            if (!confirmed)
            {
                var forward = source.Where(kv => kv.Key is not ("confirm" or "__RequestVerificationToken"))
                    .ToDictionary(kv => kv.Key, kv => (string?)kv.Value);
                return Results.Redirect(QueryHelpers.AddQueryString(opts.LogoutConfirmationPath, forward));
            }

            // The confirmation must come from the provider's own page, not a cross-site form.
            try { await _antiforgery.ValidateRequestAsync(context); }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest(OAuthError.InvalidRequest("missing or invalid antiforgery token"));
            }
        }

        // ── End the session ──────────────────────────────────────────────────
        var session = hintSessionId is not null
            ? await _sessionService.GetSessionAsync(hintSessionId, ct)
            : await _sessionService.GetCurrentSessionAsync(context, ct);

        var frontChannelUris = new List<string>();
        if (session is not null)
        {
            if (_backChannelLogout is not null && opts.BackChannelLogoutEnabled)
                await _backChannelLogout.NotifyAsync(session, opts.LogoutTokenLifetimeSeconds, ct);
            if (opts.FrontChannelLogoutEnabled)
                frontChannelUris = await FrontChannelUrisAsync(session, opts, ct);

            await _sessionService.RemoveSessionAsync(session.SessionId, ct);
        }

        Diagnostics.Log.LoggedOut(_logger, session?.ClientIds.Count ?? 0);
        await _events.LoggedOutAsync(new LoggedOutEvent(
            session?.Subject, session?.SessionId, session?.ClientIds ?? [], DateTimeOffset.UtcNow), ct);

        await context.SignOutAsync();
        context.Response.Cookies.Delete(SessionService.CookieName);

        string? target = null;
        if (!string.IsNullOrEmpty(postLogoutRedirectUri))
            target = string.IsNullOrEmpty(state)
                ? postLogoutRedirectUri
                : QueryHelpers.AddQueryString(postLogoutRedirectUri, "state", state);

        if (frontChannelUris.Count > 0)
            return Results.Content(FrontChannelPage(frontChannelUris, target), "text/html");

        return target is not null ? Results.Redirect(target) : Results.NoContent();
    }

    /// <summary>
    /// OIDC Front-Channel Logout §2–§3: the client's <c>frontchannel_logout_uri</c>, with
    /// <c>iss</c> and <c>sid</c> when the client requires them.
    /// </summary>
    private async Task<List<string>> FrontChannelUrisAsync(OidcSession session, ProviderOptions opts, CancellationToken ct)
    {
        var uris = new List<string>();
        foreach (var id in session.ClientIds)
        {
            var client = await _clientStore.FindClientAsync(id, ct);
            if (client?.FrontChannelLogoutUri is not { } uri) continue;
            uris.Add(client.FrontChannelLogoutSessionRequired
                ? QueryHelpers.AddQueryString(uri, new Dictionary<string, string?>
                {
                    ["iss"] = opts.Issuer.TrimEnd('/'),
                    ["sid"] = session.SessionId,
                })
                : uri);
        }
        return uris;
    }

    /// <summary>Renders one hidden iframe per client, then continues to <paramref name="target"/>.</summary>
    private static string FrontChannelPage(IEnumerable<string> uris, string? target)
    {
        var enc = HtmlEncoder.Default;
        var frames = string.Concat(uris.Select(u =>
            $"""<iframe src="{enc.Encode(u)}" style="display:none" title="logout"></iframe>"""));
        var next = target is null
            ? "<p>You have been signed out.</p>"
            : $"""<p>Signing you out… <a id="continue" href="{enc.Encode(target)}">Continue</a></p>""";
        var script = target is null
            ? string.Empty
            : $$"""<script>window.addEventListener("load", function () { setTimeout(function () { window.location.href = {{System.Text.Json.JsonSerializer.Serialize(target)}}; }, 1000); });</script>""";

        return $"""
            <!DOCTYPE html>
            <html>
              <head><title>Signed out</title></head>
              <body>
                {next}
                {frames}
                {script}
              </body>
            </html>
            """;
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrEmpty(value) ? null : value;
}
