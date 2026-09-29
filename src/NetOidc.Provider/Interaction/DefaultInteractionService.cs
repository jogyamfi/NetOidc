using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Interaction;

/// <summary>
/// Default implementation on top of ASP.NET Core authentication:
/// <list type="bullet">
///   <item>the End-User is whoever the default authentication scheme authenticates
///   (<c>NameIdentifier</c> or <c>sub</c> claim);</item>
///   <item><c>auth_time</c> is the <c>auth_time</c> claim when present, otherwise the
///   authentication ticket's issue time;</item>
///   <item><c>acr</c> and <c>amr</c> come from claims of the same names;</item>
///   <item>consent is read from <see cref="ConsentService"/> for clients with
///   <see cref="Client.RequireConsent"/>.</item>
/// </list>
/// </summary>
public sealed class DefaultInteractionService : IInteractionService
{
    private readonly ConsentService _consents;

    public DefaultInteractionService(ConsentService consents) => _consents = consents;

    public async Task<InteractionOutcome> EvaluateAsync(InteractionRequest request, CancellationToken ct = default)
    {
        var context = request.HttpContext;
        var resumed = request.ResumedInteraction;

        // ── Authentication ───────────────────────────────────────────────────
        var auth = await context.AuthenticateAsync();
        var user = auth.Succeeded ? auth.Principal! : context.User;
        var subject = user.Identity?.IsAuthenticated == true
            ? user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub")
            : null;
        if (subject is null)
            return InteractionOutcome.Requires(InteractionOutcomeKind.LoginRequired);

        var authTime = ReadAuthTime(user, auth.Properties);

        // A login that happened after the request was suspended satisfies prompt=login/select_account.
        // Authentication times have one-second precision, so compare at that precision.
        var suspendedAt = resumed is null ? DateTimeOffset.MaxValue : TruncateToSecond(resumed.CreatedAt);
        var freshLogin = authTime >= suspendedAt;

        if ((request.Prompt.Contains("login") || request.Prompt.Contains("select_account")) && !freshLogin)
            return InteractionOutcome.Requires(request.Prompt.Contains("login")
                ? InteractionOutcomeKind.LoginRequired
                : InteractionOutcomeKind.AccountSelectionRequired);

        // OIDC Core §3.1.2.1: re-authenticate when the last login is older than max_age
        // (a login completed for this very request always satisfies it, including max_age=0).
        if (request.MaxAge is { } maxAge && !freshLogin &&
            DateTimeOffset.UtcNow - authTime > TimeSpan.FromSeconds(maxAge))
            return InteractionOutcome.Requires(InteractionOutcomeKind.LoginRequired);

        // ── Consent ──────────────────────────────────────────────────────────
        if (request.Client.RequireConsent)
        {
            var consent = await _consents.FindAsync(request.Client.ClientId, subject, ct);
            var covered = consent is not null && request.RequestedScopes.All(consent.Scopes.Contains);
            var freshConsent = consent is not null && resumed is not null &&
                               consent.GrantedAt >= resumed.CreatedAt;

            if (!covered || (request.Prompt.Contains("consent") && !freshConsent))
                return InteractionOutcome.Requires(InteractionOutcomeKind.ConsentRequired);
        }

        return new InteractionOutcome
        {
            Kind = InteractionOutcomeKind.Completed,
            Subject = subject,
            AuthTime = authTime,
            GrantedScopes = request.RequestedScopes,
            Acr = user.FindFirstValue("acr"),
            Amr = user.FindAll("amr").Select(c => c.Value).ToList() is { Count: > 0 } amr ? amr : null,
        };
    }

    private static DateTimeOffset TruncateToSecond(DateTimeOffset value) =>
        new(value.Ticks - value.Ticks % TimeSpan.TicksPerSecond, value.Offset);

    private static DateTimeOffset ReadAuthTime(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        if (long.TryParse(user.FindFirstValue("auth_time"), out var unix))
            return DateTimeOffset.FromUnixTimeSeconds(unix);
        // Unknown authentication time is treated as "long ago" so max_age forces a login.
        return properties?.IssuedUtc ?? DateTimeOffset.MinValue;
    }
}
