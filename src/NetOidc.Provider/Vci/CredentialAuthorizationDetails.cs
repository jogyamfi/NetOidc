using System.Text.Json.Nodes;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Vci;

/// <summary>
/// <c>authorization_details</c> of type <c>openid_credential</c> (OID4VCI 1.0 §5.1.1, §6.2):
/// validation at the authorization endpoint, construction for pre-authorized codes, and the
/// credentials a token authorizes. Each authorized configuration gets the credential
/// identifier equal to its <c>credential_configuration_id</c>.
/// </summary>
public static class CredentialAuthorizationDetails
{
    public const string Type = "openid_credential";

    /// <summary>
    /// Validates the <c>openid_credential</c> entries of <paramref name="details"/> and adds their
    /// <c>credential_identifiers</c>. Returns an error description for an invalid entry.
    /// </summary>
    public static string? ValidateAndEnrich(JsonArray details, ProviderOptions opts)
    {
        foreach (var entry in details.OfType<JsonObject>().Where(e => e["type"].AsString() == Type))
        {
            if (!opts.VciEnabled)
                return "openid_credential authorization details require credential issuance";
            if (entry["credential_configuration_id"] is not JsonValue idValue || !idValue.TryGetValue<string>(out var id))
                return "openid_credential authorization details require credential_configuration_id";
            if (opts.VciCredentialConfigurations.All(c => c.Id != id))
                return $"unknown credential_configuration_id '{id}'";
            entry["credential_identifiers"] = new JsonArray(id);
        }
        return null;
    }

    /// <summary>Builds the authorization details for a pre-authorized code.</summary>
    public static string Build(IEnumerable<string> configurationIds) =>
        new JsonArray([.. configurationIds.Select(id => (JsonNode?)new JsonObject
        {
            ["type"] = Type,
            ["credential_configuration_id"] = id,
            ["credential_identifiers"] = new JsonArray(id),
        })]).ToJsonString();

    /// <summary>
    /// The credential identifiers (and hence configurations) the token's authorization details
    /// grant, mapped identifier → configuration id.
    /// </summary>
    public static Dictionary<string, string> AuthorizedIdentifiers(string? authorizationDetailsJson)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(authorizationDetailsJson) || JsonNode.Parse(authorizationDetailsJson) is not JsonArray details)
            return result;
        foreach (var entry in details.OfType<JsonObject>().Where(e => e["type"].AsString() == Type))
        {
            if (entry["credential_configuration_id"].AsString() is not { } configId) continue;
            foreach (var identifier in entry["credential_identifiers"] as JsonArray ?? [])
                if (identifier.AsString() is { } value)
                    result[value] = configId;
        }
        return result;
    }
}
