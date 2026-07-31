using System.Text.Json.Serialization;

namespace NetOidc.Provider.Errors;

/// <summary>OAuth 2.0 error response body (RFC 6749 §5.2).</summary>
public sealed record OAuthError(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string? Description = null)
{
    public static OAuthError InvalidRequest(string? description = null) => new("invalid_request", description);
    public static OAuthError InvalidClient(string? description = null) => new("invalid_client", description);
    public static OAuthError InvalidGrant(string? description = null) => new("invalid_grant", description);
    public static OAuthError UnauthorizedClient(string? description = null) => new("unauthorized_client", description);
    public static OAuthError AccessDenied(string? description = null) => new("access_denied", description);
    public static OAuthError UnsupportedResponseType(string? description = null) => new("unsupported_response_type", description);
    public static OAuthError UnsupportedGrantType(string? description = null) => new("unsupported_grant_type", description);
    public static OAuthError InvalidScope(string? description = null) => new("invalid_scope", description);
    public static OAuthError ServerError(string? description = null) => new("server_error", description);
}
