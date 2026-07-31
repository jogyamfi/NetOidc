using System.Text.Json.Serialization;

namespace NetOidc.Provider.Discovery;

/// <summary>
/// OIDC Discovery / RFC 8414 server metadata document returned by
/// <c>/.well-known/openid-configuration</c>.
/// </summary>
public sealed class DiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; init; }

    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }

    [JsonPropertyName("userinfo_endpoint")]
    public required string UserInfoEndpoint { get; init; }

    [JsonPropertyName("introspection_endpoint")]
    public string? IntrospectionEndpoint { get; init; }

    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }

    [JsonPropertyName("response_types_supported")]
    public required IReadOnlyList<string> ResponseTypesSupported { get; init; }

    [JsonPropertyName("grant_types_supported")]
    public required IReadOnlyList<string> GrantTypesSupported { get; init; }

    [JsonPropertyName("subject_types_supported")]
    public required IReadOnlyList<string> SubjectTypesSupported { get; init; }

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public required IReadOnlyList<string> TokenEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("introspection_endpoint_auth_methods_supported")]
    public IReadOnlyList<string>? IntrospectionEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("revocation_endpoint_auth_methods_supported")]
    public IReadOnlyList<string>? RevocationEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("code_challenge_methods_supported")]
    public required IReadOnlyList<string> CodeChallengeMethodsSupported { get; init; }

    [JsonPropertyName("scopes_supported")]
    public required IReadOnlyList<string> ScopesSupported { get; init; }

    [JsonPropertyName("response_modes_supported")]
    public required IReadOnlyList<string> ResponseModesSupported { get; init; }

    [JsonPropertyName("claims_parameter_supported")]
    public bool ClaimsParameterSupported { get; init; }

    [JsonPropertyName("authorization_response_iss_parameter_supported")]
    public bool AuthorizationResponseIssParameterSupported { get; init; }

    [JsonPropertyName("end_session_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EndSessionEndpoint { get; init; }

    [JsonPropertyName("registration_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistrationEndpoint { get; init; }

    [JsonPropertyName("backchannel_logout_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool BackChannelLogoutSupported { get; init; }

    [JsonPropertyName("backchannel_logout_session_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool BackChannelLogoutSessionSupported { get; init; }
}
