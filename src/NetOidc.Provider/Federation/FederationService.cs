using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Discovery;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Federation;

/// <summary>
/// Builds and signs the provider's OpenID Federation 1.1 statements: its entity configuration
/// (§3, §9) and explicit registration responses (§12.2). Both are signed with the federation
/// entity key, which is published only in the entity configuration's <c>jwks</c>.
/// </summary>
public sealed class FederationService
{
    private static readonly JsonSerializerOptions MetadataJson = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IOptions<ProviderOptions> _options;
    private readonly KeyRing _keys;
    private readonly DiscoveryService _discovery;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    public FederationService(IOptions<ProviderOptions> options, KeyRing keys, DiscoveryService discovery)
    {
        _options = options;
        _keys = keys;
        _discovery = discovery;
    }

    /// <summary>Returns this provider's signed entity configuration.</summary>
    public string BuildEntityConfiguration()
    {
        var opts = _options.Value;
        var issuer = opts.Issuer.TrimEnd('/');

        // The same metadata as the discovery document, so the two can never disagree.
        var openIdProvider = JsonSerializer.SerializeToNode(_discovery.BuildDocument(), MetadataJson)!;
        var federationEntity = JsonSerializer.SerializeToNode(opts.FederationEntityMetadata)!;

        var payload = new JsonObject
        {
            ["iss"] = issuer,
            ["sub"] = issuer,
            ["metadata"] = new JsonObject
            {
                ["openid_provider"] = openIdProvider,
                ["federation_entity"] = federationEntity,
            },
            ["jwks"] = new JsonObject { ["keys"] = JsonSerializer.SerializeToNode(_keys.GetFederationPublicJwks()) },
        };
        if (opts.FederationAuthorityHints.Count > 0)
            payload["authority_hints"] = new JsonArray([.. opts.FederationAuthorityHints.Select(h => (JsonNode?)h)]);

        var now = DateTimeOffset.UtcNow;
        return Sign(payload, "entity-statement+jwt", now, now.AddSeconds(opts.FederationEntityStatementLifetimeSeconds));
    }

    /// <summary>
    /// Builds the explicit registration response for <paramref name="client"/> registered
    /// through <paramref name="chain"/>. It never outlives the trust chain.
    /// </summary>
    public string BuildRegistrationResponse(TrustChain chain, Client client)
    {
        var opts = _options.Value;
        var metadata = (JsonObject)chain.Metadata.DeepClone();
        metadata["client_id"] = client.ClientId;
        metadata["token_endpoint_auth_method"] = client.TokenEndpointAuthMethod;
        metadata["grant_types"] = new JsonArray([.. client.AllowedGrantTypes.Select(g => (JsonNode?)g)]);
        metadata["scope"] = string.Join(' ', client.AllowedScopes);

        var payload = new JsonObject
        {
            ["iss"] = opts.Issuer.TrimEnd('/'),
            ["sub"] = chain.EntityId,
            ["aud"] = chain.EntityId,
            ["trust_anchor"] = chain.TrustAnchorId,
            ["authority_hints"] = new JsonArray(chain.ImmediateSuperior),
            ["metadata"] = new JsonObject { ["openid_relying_party"] = metadata },
            ["jwks"] = chain.LeafConfiguration.Payload["jwks"]?.DeepClone(),
        };

        var now = DateTimeOffset.UtcNow;
        var exp = now.AddSeconds(opts.FederationEntityStatementLifetimeSeconds);
        return Sign(payload, "explicit-registration-response+jwt", now, chain.ExpiresAt < exp ? chain.ExpiresAt : exp);
    }

    private string Sign(JsonObject payload, string type, DateTimeOffset issuedAt, DateTimeOffset expires)
    {
        // JsonWebTokenHandler serializes JsonElement claim values verbatim.
        var claims = payload
            .Where(p => p.Value is not null)
            .ToDictionary(p => p.Key, p => (object)JsonSerializer.SerializeToElement(p.Value));

        return _jwtHandler.CreateToken(new SecurityTokenDescriptor
        {
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = _keys.GetFederationSigningCredentials(),
            TokenType = type,
            Claims = claims,
        });
    }
}
