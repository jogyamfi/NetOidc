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

    // ── Phase 5 ───────────────────────────────────────────────────────────────

    /// <summary>RFC 9449: the DPoP proof is missing, malformed, or fails validation.</summary>
    public static OAuthError InvalidDPoPProof(string? description = null) => new("invalid_dpop_proof", description);

    /// <summary>RFC 9449 §8: the server requires a nonce in DPoP proofs.</summary>
    public static OAuthError UseDPoPNonce(string? description = null) => new("use_dpop_nonce", description);

    // ── Phase 6 ───────────────────────────────────────────────────────────────

    /// <summary>RFC 8628 §3.5 / CIBA §11: authorization has not yet been granted by the user.</summary>
    public static OAuthError AuthorizationPending(string? description = null) => new("authorization_pending", description);

    /// <summary>RFC 8628 §3.5 / CIBA §11: the client is polling too frequently.</summary>
    public static OAuthError SlowDown(string? description = null) => new("slow_down", description);

    /// <summary>RFC 8628 §3.5: the device code has expired before the user authorized.</summary>
    public static OAuthError ExpiredToken(string? description = null) => new("expired_token", description);

    /// <summary>CIBA: the authorization request was denied by the user or timed out.</summary>
    public static OAuthError AccessDeniedCiba(string? description = null) => new("access_denied", description);

    // ── Phase 8 — VCI (OID4VCI 1.0) ──────────────────────────────────────────

    /// <summary>OID4VCI: the presented access token is invalid or expired.</summary>
    public static OAuthError InvalidToken(string? description = null) => new("invalid_token", description);

    /// <summary>OID4VCI: the credential proof (proof JWT) is invalid.</summary>
    public static OAuthError InvalidProof(string? description = null) => new("invalid_proof", description);

    /// <summary>OID4VCI: the c_nonce is invalid, expired, or already consumed.</summary>
    public static OAuthError InvalidNonce(string? description = null) => new("invalid_nonce", description);
}
