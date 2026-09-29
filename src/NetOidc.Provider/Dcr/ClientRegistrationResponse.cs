using System.Text.Json.Serialization;

namespace NetOidc.Provider.Dcr;

/// <summary>
/// JSON body returned from DCR create/read/update operations (RFC 7591 §3.2 / RFC 7592 §3).
/// </summary>
public sealed class ClientRegistrationResponse
{
    [JsonPropertyName("client_id")]
    public required string ClientId { get; init; }

    [JsonPropertyName("client_secret")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientSecret { get; init; }

    [JsonPropertyName("client_id_issued_at")]
    public long ClientIdIssuedAt { get; init; }

    /// <summary>0 = non-expiring (required by RFC 7591 §3.2.1).</summary>
    [JsonPropertyName("client_secret_expires_at")]
    public long ClientSecretExpiresAt { get; init; }

    [JsonPropertyName("registration_access_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistrationAccessToken { get; init; }

    [JsonPropertyName("registration_client_uri")]
    public required string RegistrationClientUri { get; init; }

    // ── Echoed client metadata ───────────────────────────────────────────────

    [JsonPropertyName("token_endpoint_auth_method")]
    public required string TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("grant_types")]
    public required IReadOnlyList<string> GrantTypes { get; init; }

    [JsonPropertyName("response_types")]
    public required IReadOnlyList<string> ResponseTypes { get; init; }

    [JsonPropertyName("redirect_uris")]
    public required IReadOnlyList<string> RedirectUris { get; init; }

    [JsonPropertyName("scope")]
    public required string Scope { get; init; }

    [JsonPropertyName("client_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientName { get; init; }

    [JsonPropertyName("client_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientUri { get; init; }

    [JsonPropertyName("logo_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LogoUri { get; init; }

    [JsonPropertyName("contacts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Contacts { get; init; }

    [JsonPropertyName("backchannel_logout_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BackChannelLogoutUri { get; init; }

    [JsonPropertyName("backchannel_logout_session_required")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool BackChannelLogoutSessionRequired { get; init; }

    [JsonPropertyName("post_logout_redirect_uris")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? PostLogoutRedirectUris { get; init; }

    [JsonPropertyName("jwks")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Text.Json.JsonElement? Jwks { get; init; }

    [JsonPropertyName("id_token_signed_response_alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdTokenSignedResponseAlg { get; init; }

    [JsonPropertyName("id_token_encrypted_response_alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdTokenEncryptedResponseAlg { get; init; }

    [JsonPropertyName("id_token_encrypted_response_enc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdTokenEncryptedResponseEnc { get; init; }

    [JsonPropertyName("userinfo_signed_response_alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserInfoSignedResponseAlg { get; init; }

    [JsonPropertyName("userinfo_encrypted_response_alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserInfoEncryptedResponseAlg { get; init; }

    [JsonPropertyName("userinfo_encrypted_response_enc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserInfoEncryptedResponseEnc { get; init; }

    [JsonPropertyName("request_object_signing_alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RequestObjectSigningAlg { get; init; }

    [JsonPropertyName("authorization_signed_response_alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthorizationSignedResponseAlg { get; init; }

    [JsonPropertyName("require_signed_request_object")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool RequireSignedRequestObject { get; init; }
}
