using Microsoft.AspNetCore.Http;

namespace NetOidc.Provider.Interaction;

/// <summary>Outcome of a successful interaction check (user authenticated + consented).</summary>
public sealed class InteractionResult
{
    public required string Subject { get; init; }
    public required IReadOnlyList<string> GrantedScopes { get; init; }
}

/// <summary>
/// Determines whether the current request has a logged-in user who has consented
/// to the requested scopes. Return <c>null</c> to trigger a login/consent redirect.
/// </summary>
public interface IInteractionService
{
    Task<InteractionResult?> GetInteractionResultAsync(
        HttpContext context,
        string clientId,
        IReadOnlyList<string> requestedScopes,
        CancellationToken ct = default);
}
