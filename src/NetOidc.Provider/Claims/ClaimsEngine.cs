using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetOidc.Provider.Claims;

/// <summary>
/// Parses and applies the OIDC 'claims' request parameter (OIDC Core §5.5).
/// </summary>
public static class ClaimsEngine
{
    /// <summary>
    /// Parses the raw 'claims' JSON parameter into a typed request object.
    /// Returns <c>null</c> if the input is absent or unparseable.
    /// </summary>
    public static ParsedClaimsRequest? Parse(string? claimsJson)
    {
        if (string.IsNullOrWhiteSpace(claimsJson)) return null;
        try
        {
            if (JsonNode.Parse(claimsJson) is not JsonObject obj) return null;
            return new ParsedClaimsRequest(
                IdToken: ParseSection(obj["id_token"] as JsonObject),
                UserInfo: ParseSection(obj["userinfo"] as JsonObject));
        }
        catch (JsonException)
        {
            return null;
        }
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
                values = [.. arr.Select(v => v?.GetValue<string>() ?? string.Empty)];
            else if (claimObj["value"] is JsonNode single)
                values = [single.GetValue<string>()];

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
