using System.Text.Json;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Token;

/// <summary>Parses and authorises RFC 8707 resource indicators.</summary>
public static class ResourceIndicators
{
    /// <summary>
    /// Splits a <c>resource</c> parameter value. Repeated query/form parameters are joined with
    /// spaces by the endpoints; request objects may carry a JSON array.
    /// </summary>
    public static IReadOnlyList<string> Split(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        var trimmed = value.Trim();
        if (trimmed.StartsWith('['))
        {
            try
            {
                return JsonSerializer.Deserialize<string[]>(trimmed)?.Where(v => !string.IsNullOrEmpty(v)).ToArray() ?? [];
            }
            catch (JsonException)
            {
                return [trimmed];
            }
        }
        return trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// Validates requested resources (RFC 8707 §2): absolute URIs without a fragment that the
    /// provider and client allow. Returns an <c>invalid_target</c> description on failure.
    /// </summary>
    public static string? Validate(IReadOnlyList<string> resources, ProviderOptions opts, Client client)
    {
        foreach (var resource in resources)
        {
            if (!Uri.TryCreate(resource, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
                return $"resource '{resource}' must be an absolute URI without a fragment";
            if (!opts.AllowedResources.Contains(resource) ||
                (client.AllowedResources.Count > 0 && !client.AllowedResources.Contains(resource)))
                return $"resource '{resource}' is not allowed";
        }
        return null;
    }
}
