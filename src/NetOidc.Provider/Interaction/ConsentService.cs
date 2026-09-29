using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Interaction;

/// <summary>
/// Records and looks up End-User consent. The host's consent page calls
/// <see cref="GrantAsync"/> after the End-User approves.
/// </summary>
public sealed class ConsentService
{
    private readonly IAdapter<Consent> _consents;

    public ConsentService(IAdapter<Consent> consents) => _consents = consents;

    /// <summary>Returns the stored consent for the (client, subject) pair, if any.</summary>
    public Task<Consent?> FindAsync(string clientId, string subject, CancellationToken ct = default) =>
        _consents.FindAsync(Consent.KeyFor(clientId, subject), ct);

    /// <summary>
    /// Records that <paramref name="subject"/> consented to <paramref name="scopes"/> for
    /// <paramref name="clientId"/>. Scopes accumulate with any previous consent.
    /// </summary>
    public async Task GrantAsync(
        string clientId, string subject, IEnumerable<string> scopes,
        TimeSpan? lifetime = null, CancellationToken ct = default)
    {
        var existing = await FindAsync(clientId, subject, ct);
        var merged = (existing?.Scopes ?? []).Union(scopes, StringComparer.Ordinal).ToList();
        var now = DateTimeOffset.UtcNow;
        await _consents.StoreAsync(Consent.KeyFor(clientId, subject), new Consent
        {
            ClientId = clientId,
            Subject = subject,
            Scopes = merged,
            GrantedAt = now,
            ExpiresAt = lifetime is null ? null : now + lifetime,
        }, lifetime, ct);
    }

    /// <summary>Withdraws all consent the subject gave the client.</summary>
    public Task RevokeAsync(string clientId, string subject, CancellationToken ct = default) =>
        _consents.RemoveAsync(Consent.KeyFor(clientId, subject), ct);
}
