using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Federation;

/// <summary>A parsed (not yet verified) OpenID Federation entity statement (§3).</summary>
internal sealed class EntityStatement
{
    public const string MediaType = "application/entity-statement+jwt";

    private EntityStatement(string raw, JsonObject payload)
    {
        Raw = raw;
        Payload = payload;
    }

    public string Raw { get; }
    public JsonObject Payload { get; }

    public string? Issuer => Payload["iss"].AsString();
    public string? Subject => Payload["sub"].AsString();
    public DateTimeOffset? ExpiresAt =>
        Payload["exp"] is JsonValue exp && exp.TryGetValue<long>(out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;

    /// <summary>The <c>jwks</c> claim: the subject's federation entity keys.</summary>
    public JsonWebKeySet? Jwks =>
        Payload["jwks"] is JsonObject jwks ? TryJwks(jwks.ToJsonString()) : null;

    public IReadOnlyList<string> AuthorityHints =>
        Payload["authority_hints"] is JsonArray hints
            ? hints.Select(h => h.AsString()).Where(h => !string.IsNullOrEmpty(h)).Select(h => h!).ToList()
            : [];

    public JsonObject? Metadata(string entityType) => Payload["metadata"]?[entityType] as JsonObject;

    public JsonObject? MetadataPolicy(string entityType) => Payload["metadata_policy"]?[entityType] as JsonObject;

    /// <summary>The <c>federation_fetch_endpoint</c> of an intermediate or trust anchor.</summary>
    public string? FetchEndpoint => Payload["metadata"]?["federation_entity"]?["federation_fetch_endpoint"].AsString();

    /// <summary>Parses the compact JWT; returns <c>null</c> when it is not a well-formed entity statement.</summary>
    public static EntityStatement? Parse(string raw)
    {
        try
        {
            var token = new JsonWebToken(raw);
            var payload = JsonNode.Parse(Base64UrlEncoder.Decode(token.EncodedPayload)) as JsonObject;
            return payload is null ? null : new EntityStatement(raw, payload);
        }
        catch (Exception ex) when (ex is ArgumentException or JsonException or FormatException or SecurityTokenException)
        {
            return null;
        }
    }

    /// <summary>
    /// Verifies the signature with <paramref name="keys"/>, the lifetime, and the explicit type.
    /// </summary>
    public async Task<bool> VerifyAsync(JsonWebKeySet? keys, string expectedType = "entity-statement+jwt")
    {
        if (keys is null || keys.Keys.Count == 0) return false;
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(Raw, new TokenValidationParameters
        {
            IssuerSigningKeys = keys.GetSigningKeys(),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidTypes = [expectedType],
            ClockSkew = TimeSpan.FromSeconds(30),
        });
        return result.IsValid;
    }

    internal static JsonWebKeySet? TryJwks(string json)
    {
        try { return new JsonWebKeySet(json); }
        catch (ArgumentException) { return null; }
    }
}
