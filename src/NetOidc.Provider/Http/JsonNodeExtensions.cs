using System.Text.Json.Nodes;

namespace NetOidc.Provider.Http;

internal static class JsonNodeExtensions
{
    /// <summary>
    /// The node's string value, or <c>null</c> when it is absent or not a string. Unlike the
    /// explicit <c>(string?)</c> conversion it never throws on attacker-supplied JSON.
    /// </summary>
    public static string? AsString(this JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;
}
