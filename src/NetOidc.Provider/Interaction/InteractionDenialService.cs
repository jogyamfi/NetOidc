using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Interaction;

/// <summary>
/// Lets the host's login or consent page end a suspended authorization request with an error
/// instead of completing it — the End-User pressed "cancel" or refused consent (OIDC Core
/// §3.1.2.6). Call <see cref="DenyAsync"/> with the page's <c>returnUrl</c>, then redirect to it;
/// the provider returns the error to the client's redirect URI.
/// </summary>
public sealed class InteractionDenialService
{
    private static readonly HashSet<string> AllowedErrors = new(StringComparer.Ordinal)
    {
        "access_denied", "login_required", "consent_required", "interaction_required", "account_selection_required",
    };

    private readonly IAdapter<PendingInteraction> _interactions;
    private readonly IOptions<ProviderOptions> _options;

    public InteractionDenialService(IAdapter<PendingInteraction> interactions, IOptions<ProviderOptions> options)
    {
        _interactions = interactions;
        _options = options;
    }

    /// <summary>
    /// Marks the interaction named in <paramref name="returnUrl"/> (its <c>interaction</c>
    /// parameter) as denied. Returns <c>false</c> when there is no such pending interaction.
    /// </summary>
    /// <param name="error"><c>access_denied</c> (default) or another OIDC interaction error.</param>
    public async Task<bool> DenyAsync(
        string returnUrl, string error = "access_denied", string? description = null, CancellationToken ct = default)
    {
        if (!AllowedErrors.Contains(error))
            throw new ArgumentException($"'{error}' is not an authorization interaction error.", nameof(error));

        var query = returnUrl.IndexOf('?') is var q and >= 0 ? returnUrl[q..] : string.Empty;
        if (!QueryHelpers.ParseQuery(query).TryGetValue("interaction", out var id) || string.IsNullOrEmpty(id))
            return false;

        var pending = await _interactions.FindAsync(id!, ct);
        if (pending is null)
            return false;

        var remaining = pending.CreatedAt.AddSeconds(_options.Value.InteractionLifetimeSeconds) - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
            return false;
        await _interactions.StoreAsync(pending.InteractionId, new PendingInteraction
        {
            InteractionId = pending.InteractionId,
            ClientId = pending.ClientId,
            Kind = pending.Kind,
            CreatedAt = pending.CreatedAt,
            DenialError = error,
            DenialDescription = description,
        }, remaining, ct);
        return true;
    }
}
