using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Claims;

/// <summary>Where a set of End-User claims will be delivered.</summary>
public enum ClaimsDestination
{
    IdToken,
    UserInfo,
}

/// <summary>Input to <see cref="ProviderOptions.FindUserClaims"/>.</summary>
/// <param name="Subject">The End-User's local subject identifier.</param>
/// <param name="ClientId">The client the claims are released to.</param>
/// <param name="Scopes">Scopes granted to the client.</param>
/// <param name="ClaimNames">
/// Every claim name that may be released: those mapped from <paramref name="Scopes"/> plus those
/// individually requested with the <c>claims</c> parameter. Other returned claims are dropped.
/// </param>
/// <param name="Destination">Where the claims are going.</param>
public sealed record UserClaimsRequest(
    string Subject,
    string ClientId,
    IReadOnlyList<string> Scopes,
    IReadOnlyCollection<string> ClaimNames,
    ClaimsDestination Destination);

/// <summary>
/// Resolves End-User claims through <see cref="ProviderOptions.FindUserClaims"/> and releases
/// only claims justified by granted scopes (OIDC Core §5.4) or the <c>claims</c> request (§5.5).
/// </summary>
public sealed class UserClaimsService
{
    private readonly IOptions<ProviderOptions> _options;

    public UserClaimsService(IOptions<ProviderOptions> options) => _options = options;

    /// <summary>
    /// Returns the claims for <paramref name="destination"/>, excluding <c>sub</c> (which the
    /// caller sets). Scope-derived claims are included only when
    /// <paramref name="includeScopeClaims"/> is true.
    /// </summary>
    public async Task<Dictionary<string, object>> GetClaimsAsync(
        string subject, Client client, IReadOnlyList<string> scopes,
        ParsedClaimsRequest? claimsRequest, ClaimsDestination destination,
        bool includeScopeClaims, CancellationToken ct)
    {
        var opts = _options.Value;
        var allowed = includeScopeClaims
            ? ClaimsEngine.ClaimsForScopes(scopes, opts.Scopes)
            : new HashSet<string>(StringComparer.Ordinal);

        var requested = destination == ClaimsDestination.IdToken
            ? claimsRequest?.IdToken
            : claimsRequest?.UserInfo;
        if (requested is not null)
            allowed.UnionWith(requested.Keys);

        // Never let a claims request override protocol claims.
        allowed.ExceptWith(ProtocolClaims);
        if (allowed.Count == 0)
            return [];

        var found = await opts.FindUserClaims(
            new UserClaimsRequest(subject, client.ClientId, scopes, allowed, destination), ct);

        return found
            .Where(kv => allowed.Contains(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
    }

    /// <summary>Claims owned by the protocol that user-claim sources must never supply.</summary>
    private static readonly HashSet<string> ProtocolClaims = new(StringComparer.Ordinal)
    {
        "sub", "iss", "aud", "exp", "iat", "nbf", "jti", "auth_time", "nonce", "acr", "amr",
        "azp", "at_hash", "c_hash", "sid", "cnf", "scope", "client_id",
    };
}
