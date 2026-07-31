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
}
