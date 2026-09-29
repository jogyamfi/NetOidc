using System.Text.Json.Nodes;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Federation;

/// <summary>
/// Applies OpenID Federation metadata policies (§6.1) to entity metadata. Supports the
/// standard operators <c>value</c>, <c>add</c>, <c>default</c>, <c>one_of</c>,
/// <c>subset_of</c>, <c>superset_of</c> and <c>essential</c>.
/// </summary>
public static class MetadataPolicy
{
    /// <summary>
    /// Applies <paramref name="policy"/> to <paramref name="metadata"/> in place. Returns an error
    /// description when the metadata violates the policy (or the policy uses an unknown operator),
    /// otherwise <c>null</c>.
    /// </summary>
    public static string? Apply(JsonObject metadata, JsonObject policy)
    {
        foreach (var (claim, node) in policy)
        {
            if (node is not JsonObject operators)
                return $"policy for '{claim}' must be an object";

            foreach (var op in operators.Select(o => o.Key))
                if (op is not ("value" or "add" or "default" or "one_of" or "subset_of" or "superset_of" or "essential"))
                    return $"unsupported metadata policy operator '{op}' for '{claim}'";

            // `scope` is a space-separated string that the operators treat as a list (§6.1.3).
            var isScope = claim == "scope";
            if (isScope)
            {
                if (metadata[claim] is not null) metadata[claim] = ScopeList(metadata[claim]);
                foreach (var op in new[] { "value", "default" })
                    if (operators[op] is JsonValue)
                        operators = WithOperator(operators, op, ScopeList(operators[op]));
            }

            var error = ApplyOperators(metadata, claim, operators);

            if (isScope && metadata[claim] is JsonArray scopes)
                metadata[claim] = string.Join(' ', scopes.Select(s => s.AsString()));
            if (error is not null)
                return error;
        }
        return null;
    }

    private static string? ApplyOperators(JsonObject metadata, string claim, JsonObject operators)
    {
        // Operators are applied in the order defined by §6.1.3.1.
        if (operators.TryGetPropertyValue("value", out var value))
        {
            if (value is null) metadata.Remove(claim);
            else metadata[claim] = value.DeepClone();
        }

        if (operators["add"] is JsonArray add)
        {
            var current = metadata[claim] as JsonArray ?? [];
            foreach (var item in add)
                if (!current.Any(c => JsonNode.DeepEquals(c, item)))
                    current.Add(item?.DeepClone());
            metadata[claim] = current.DeepClone();
        }

        if (operators.TryGetPropertyValue("default", out var @default) && metadata[claim] is null && @default is not null)
            metadata[claim] = @default.DeepClone();

        if (operators["one_of"] is JsonArray oneOf && metadata[claim] is { } single &&
            !oneOf.Any(o => JsonNode.DeepEquals(o, single)))
            return $"'{claim}' must be one of {oneOf.ToJsonString()}";

        if (operators["subset_of"] is JsonArray subsetOf && metadata[claim] is JsonArray values)
        {
            var kept = new JsonArray();
            foreach (var v in values)
                if (subsetOf.Any(s => JsonNode.DeepEquals(s, v)))
                    kept.Add(v?.DeepClone());
            if (kept.Count == 0) metadata.Remove(claim);
            else metadata[claim] = kept;
        }

        if (operators["superset_of"] is JsonArray supersetOf)
        {
            var have = metadata[claim] as JsonArray ?? [];
            var missing = supersetOf.Where(s => !have.Any(h => JsonNode.DeepEquals(h, s))).ToList();
            if (missing.Count > 0)
                return $"'{claim}' must include {new JsonArray([.. missing.Select(m => m?.DeepClone())]).ToJsonString()}";
        }

        if (operators["essential"] is JsonValue essential && essential.TryGetValue<bool>(out var required) &&
            required && metadata[claim] is null)
            return $"'{claim}' is required by policy";
        return null;
    }

    private static JsonArray? ScopeList(JsonNode? node) => node switch
    {
        JsonValue v when v.TryGetValue<string>(out var s) =>
            new JsonArray([.. s.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(x => (JsonNode?)x)]),
        JsonArray a => (JsonArray)a.DeepClone(),
        _ => null,
    };

    private static JsonObject WithOperator(JsonObject operators, string name, JsonNode? value)
    {
        var copy = (JsonObject)operators.DeepClone();
        copy[name] = value;
        return copy;
    }
}
