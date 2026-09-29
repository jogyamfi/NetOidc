using Microsoft.AspNetCore.Http;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Interaction;

/// <summary>Everything the interaction service needs to decide on an authorization request.</summary>
public sealed class InteractionRequest
{
    public required HttpContext HttpContext { get; init; }
    public required Client Client { get; init; }
    public required IReadOnlyList<string> RequestedScopes { get; init; }

    /// <summary>OIDC <c>prompt</c> values (<c>none</c>, <c>login</c>, <c>consent</c>, <c>select_account</c>).</summary>
    public IReadOnlySet<string> Prompt { get; init; } = new HashSet<string>();

    /// <summary>OIDC <c>max_age</c> in seconds, or <c>null</c>.</summary>
    public int? MaxAge { get; init; }

    /// <summary>
    /// <c>sub</c> of a valid <c>id_token_hint</c> as issued to this client (public or pairwise).
    /// The provider itself checks it against the authenticated End-User.
    /// </summary>
    public string? IdTokenHintSubject { get; init; }

    public string? LoginHint { get; init; }
    public IReadOnlyList<string> AcrValues { get; init; } = [];
    public string? UiLocales { get; init; }

    /// <summary>
    /// The suspended interaction this request resumes, if any. A login or consent that happened
    /// after its <see cref="PendingInteraction.CreatedAt"/> satisfies <c>prompt=login</c> /
    /// <c>prompt=consent</c>.
    /// </summary>
    public PendingInteraction? ResumedInteraction { get; init; }
}

/// <summary>What must happen before the authorization request can complete.</summary>
public enum InteractionOutcomeKind
{
    /// <summary>The End-User is authenticated and has consented.</summary>
    Completed,

    /// <summary>The End-User must (re-)authenticate.</summary>
    LoginRequired,

    /// <summary>The End-User must consent to the requested scopes.</summary>
    ConsentRequired,

    /// <summary>The End-User must choose an account.</summary>
    AccountSelectionRequired,
}

/// <summary>Outcome of <see cref="IInteractionService.EvaluateAsync"/>.</summary>
public sealed class InteractionOutcome
{
    public required InteractionOutcomeKind Kind { get; init; }

    /// <summary>The End-User's local subject (set when <see cref="Kind"/> is Completed).</summary>
    public string? Subject { get; init; }

    /// <summary>When the End-User last authenticated (OIDC Core <c>auth_time</c>).</summary>
    public DateTimeOffset AuthTime { get; init; }

    public IReadOnlyList<string> GrantedScopes { get; init; } = [];

    /// <summary>Authentication Context Reference achieved (e.g. "urn:mace:incommon:iap:silver").</summary>
    public string? Acr { get; init; }

    /// <summary>Authentication Methods References (e.g. ["pwd", "otp"]).</summary>
    public IReadOnlyList<string>? Amr { get; init; }

    public static InteractionOutcome Requires(InteractionOutcomeKind kind) => new() { Kind = kind };
}

/// <summary>
/// Decides whether an authorization request can complete, or which interaction (login,
/// consent, account selection) must happen first. The provider turns a non-completed outcome
/// into a redirect to the login/consent page, or into an OIDC error when <c>prompt=none</c>.
/// </summary>
public interface IInteractionService
{
    Task<InteractionOutcome> EvaluateAsync(InteractionRequest request, CancellationToken ct = default);
}
