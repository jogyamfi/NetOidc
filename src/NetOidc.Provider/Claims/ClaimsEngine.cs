using System.Text.Json;
using System.Text.Json.Nodes;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Claims;

/// <summary>
/// Parses the OIDC <c>claims</c> request parameter (OIDC Core §5.5) and maps scopes to the
/// claims they release (§5.4).
/// </summary>
public static class ClaimsEngine
{
    /// <summary>Claims released by the standard OIDC scopes (OIDC Core §5.4).</summary>
    public static readonly IReadOnlyDictionary<string, string[]> StandardScopeClaims =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["profile"] =
            [
                "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username",
                "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
            ],
            ["email"] = ["email", "email_verified"],
            ["address"] = ["address"],
            ["phone"] = ["phone_number", "phone_number_verified"],
        };

    /// <summary>
    /// Parses the raw 'claims' JSON parameter into a typed request object.
    /// Returns <c>null</c> if the input is absent or unparseable.
    /// </summary>
    public static ParsedClaimsRequest? Parse(string? claimsJson) =>
        TryParse(claimsJson, out var parsed, out _) ? parsed : null;

    /// <summary>
    /// Parses the 'claims' parameter, reporting malformed input. An absent parameter succeeds
    /// with a <c>null</c> result.
    /// </summary>
    public static bool TryParse(string? claimsJson, out ParsedClaimsRequest? parsed, out string? error)
    {
        parsed = null;
        error = null;
        if (string.IsNullOrWhiteSpace(claimsJson)) return true;
        try
        {
            if (JsonNode.Parse(claimsJson) is not JsonObject obj)
            {
                error = "claims must be a JSON object";
                return false;
            }
            parsed = new ParsedClaimsRequest(
                IdToken: ParseSection(obj["id_token"] as JsonObject),
                UserInfo: ParseSection(obj["userinfo"] as JsonObject));
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            error = "claims is not a valid claims request";
            return false;
        }
    }

    /// <summary>
    /// Returns the claim names <paramref name="scopes"/> release, using
    /// <see cref="Scope.Claims"/> for custom scopes and <see cref="StandardScopeClaims"/> otherwise.
    /// </summary>
    public static HashSet<string> ClaimsForScopes(IEnumerable<string> scopes, IEnumerable<Scope> registered)
    {
        var byName = registered.ToDictionary(s => s.Name, StringComparer.Ordinal);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var scope in scopes)
        {
            if (byName.TryGetValue(scope, out var def) && def.Claims.Count > 0)
                names.UnionWith(def.Claims);
            else if (StandardScopeClaims.TryGetValue(scope, out var standard))
                names.UnionWith(standard);
        }
        return names;
    }

    /// <summary>
    /// Merges claims requested for a given destination (<c>id_token</c> or <c>userinfo</c>)
    /// from <paramref name="requested"/> into <paramref name="claims"/>, sourcing values
    /// from <paramref name="available"/>.
    /// </summary>
    public static void MergeClaims(
        IReadOnlyDictionary<string, ClaimRequest> requested,
        IReadOnlyDictionary<string, object> available,
        IDictionary<string, object> claims)
    {
        foreach (var (name, _) in requested)
        {
            if (!claims.ContainsKey(name) && available.TryGetValue(name, out var value))
                claims[name] = value;
        }
    }

    private static IReadOnlyDictionary<string, ClaimRequest> ParseSection(JsonObject? section)
    {
        if (section is null) return new Dictionary<string, ClaimRequest>(0);
        var result = new Dictionary<string, ClaimRequest>(section.Count, StringComparer.Ordinal);
        foreach (var (name, value) in section)
        {
            if (value is null || value is not JsonObject claimObj)
            {
                result[name] = new ClaimRequest(Essential: false, Values: null);
                continue;
            }

            var essential = claimObj["essential"]?.GetValue<bool>() ?? false;
            string[]? values = null;
            if (claimObj["values"] is JsonArray arr)
                values = [.. arr.Select(v => v?.ToString() ?? string.Empty)];
            else if (claimObj["value"] is JsonNode single)
                values = [single.ToString()];

            result[name] = new ClaimRequest(Essential: essential, Values: values);
        }
        return result;
    }
}

/// <param name="Essential">Whether the claim is essential (login may fail if missing).</param>
/// <param name="Values">Acceptable values requested by the RP, or <c>null</c> for any value.</param>
public sealed record ClaimRequest(bool Essential, string[]? Values);

/// <summary>Parsed 'claims' request parameter split by token destination.</summary>
public sealed record ParsedClaimsRequest(
    IReadOnlyDictionary<string, ClaimRequest> IdToken,
    IReadOnlyDictionary<string, ClaimRequest> UserInfo);
