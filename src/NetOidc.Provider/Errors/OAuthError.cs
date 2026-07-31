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

    // ── Phase 4 ───────────────────────────────────────────────────────────────

    /// <summary>RFC 8707: the requested resource indicator is invalid or unsupported.</summary>
    public static OAuthError InvalidTarget(string? description = null) => new("invalid_target", description);

    /// <summary>RFC 9396: an authorization_details type is unknown or the structure is invalid.</summary>
    public static OAuthError InvalidAuthorizationDetails(string? description = null) => new("invalid_authorization_details", description);

    /// <summary>RFC 9126: pushed authorization request_uri is invalid, expired, or already consumed.</summary>
    public static OAuthError InvalidRequestUri(string? description = null) => new("invalid_request_uri", description);

    /// <summary>RFC 9101: the request JWT (request object) is invalid or its signature cannot be verified.</summary>
    public static OAuthError InvalidRequestObject(string? description = null) => new("invalid_request_object", description);

    /// <summary>RFC 8693: the type identifier of the subject_token is not supported.</summary>
    public static OAuthError InvalidTokenType(string? description = null) => new("invalid_token_type", description);
}
