using System.Text.Json.Serialization;

namespace NetOidc.Provider.Dcr;

/// <summary>
/// JSON body sent to <c>POST /connect/register</c> (RFC 7591 §2 + OIDC Registration §3.1).
/// All fields are optional; defaults are applied by <see cref="DynamicRegistrationEndpointHandler"/>.
/// </summary>
public sealed class ClientRegistrationRequest
{
    [JsonPropertyName("redirect_uris")]
    public IReadOnlyList<string>? RedirectUris { get; init; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("grant_types")]
    public IReadOnlyList<string>? GrantTypes { get; init; }

    [JsonPropertyName("response_types")]
    public IReadOnlyList<string>? ResponseTypes { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; init; }

    [JsonPropertyName("client_uri")]
    public string? ClientUri { get; init; }

    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; init; }

    [JsonPropertyName("contacts")]
    public IReadOnlyList<string>? Contacts { get; init; }

    [JsonPropertyName("backchannel_logout_uri")]
    public string? BackChannelLogoutUri { get; init; }

    [JsonPropertyName("backchannel_logout_session_required")]
    public bool? BackChannelLogoutSessionRequired { get; init; }

    [JsonPropertyName("post_logout_redirect_uris")]
    public IReadOnlyList<string>? PostLogoutRedirectUris { get; init; }

    [JsonPropertyName("require_pkce")]
    public bool? RequirePkce { get; init; }

    // ── Keys and algorithms (RFC 7591 §2, OIDC Registration §2, RFC 9101 §10.5) ──

    [JsonPropertyName("jwks")]
    public System.Text.Json.JsonElement? Jwks { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    [JsonPropertyName("id_token_signed_response_alg")]
    public string? IdTokenSignedResponseAlg { get; init; }

    [JsonPropertyName("id_token_encrypted_response_alg")]
    public string? IdTokenEncryptedResponseAlg { get; init; }

    [JsonPropertyName("id_token_encrypted_response_enc")]
    public string? IdTokenEncryptedResponseEnc { get; init; }

    [JsonPropertyName("userinfo_signed_response_alg")]
    public string? UserInfoSignedResponseAlg { get; init; }

    [JsonPropertyName("userinfo_encrypted_response_alg")]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    [JsonPropertyName("userinfo_encrypted_response_enc")]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    [JsonPropertyName("request_object_signing_alg")]
    public string? RequestObjectSigningAlg { get; init; }

    [JsonPropertyName("authorization_signed_response_alg")]
    public string? AuthorizationSignedResponseAlg { get; init; }

    [JsonPropertyName("require_signed_request_object")]
    public bool? RequireSignedRequestObject { get; init; }

    // ── OpenID Connect RP Metadata Choices 1.0: the RP lists what it supports and the
    //    provider chooses, returning the singular parameter in the response. ──

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public IReadOnlyList<string>? TokenEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public IReadOnlyList<string>? IdTokenSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("id_token_encryption_alg_values_supported")]
    public IReadOnlyList<string>? IdTokenEncryptionAlgValuesSupported { get; init; }

    [JsonPropertyName("id_token_encryption_enc_values_supported")]
    public IReadOnlyList<string>? IdTokenEncryptionEncValuesSupported { get; init; }

    [JsonPropertyName("userinfo_signing_alg_values_supported")]
    public IReadOnlyList<string>? UserInfoSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("userinfo_encryption_alg_values_supported")]
    public IReadOnlyList<string>? UserInfoEncryptionAlgValuesSupported { get; init; }

    [JsonPropertyName("userinfo_encryption_enc_values_supported")]
    public IReadOnlyList<string>? UserInfoEncryptionEncValuesSupported { get; init; }

    [JsonPropertyName("request_object_signing_alg_values_supported")]
    public IReadOnlyList<string>? RequestObjectSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("authorization_signing_alg_values_supported")]
    public IReadOnlyList<string>? AuthorizationSigningAlgValuesSupported { get; init; }
}
