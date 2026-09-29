namespace NetOidc.Provider.Abstractions.Events;

/// <summary>Raised after any successful token grant.</summary>
public sealed record TokenIssuedEvent(
    string ClientId,
    string? Subject,
    string GrantType,
    IReadOnlyList<string> Scopes,
    DateTimeOffset IssuedAt);

/// <summary>Raised when the authorization endpoint issues a code or token successfully.</summary>
public sealed record AuthorizationSucceededEvent(
    string ClientId,
    string Subject,
    string ResponseType,
    IReadOnlyList<string> GrantedScopes,
    DateTimeOffset IssuedAt);

/// <summary>Raised when the token introspection endpoint returns a result.</summary>
public sealed record TokenIntrospectedEvent(
    string CallerClientId,
    bool Active,
    string? TokenSubject,
    DateTimeOffset IntrospectedAt);

/// <summary>Raised after a token is revoked.</summary>
public sealed record TokenRevokedEvent(
    string CallerClientId,
    string? TokenSubject,
    DateTimeOffset RevokedAt);

/// <summary>Raised when the UserInfo endpoint is called successfully.</summary>
public sealed record UserInfoRequestedEvent(
    string Subject,
    IReadOnlyList<string> Scopes,
    DateTimeOffset RequestedAt);

/// <summary>Raised when client authentication fails. <paramref name="ClientId"/> is the claimed id, if any.</summary>
public sealed record ClientAuthenticationFailedEvent(
    string? ClientId,
    string Endpoint,
    string Reason,
    DateTimeOffset OccurredAt);

/// <summary>Raised when the token endpoint rejects a request (after or during client authentication).</summary>
public sealed record TokenRequestFailedEvent(
    string? ClientId,
    string GrantType,
    string Error,
    string? Description,
    DateTimeOffset OccurredAt);

/// <summary>Raised when the authorization endpoint returns an error.</summary>
public sealed record AuthorizationFailedEvent(
    string? ClientId,
    string Error,
    string? Description,
    DateTimeOffset OccurredAt);

/// <summary>Raised when an End-User session ends; <paramref name="ClientIds"/> are the clients notified.</summary>
public sealed record LoggedOutEvent(
    string? Subject,
    string? SessionId,
    IReadOnlyList<string> ClientIds,
    DateTimeOffset OccurredAt);

/// <summary>Raised when an End-User approves or denies a device (<c>device_code</c>) or CIBA request.</summary>
public sealed record AuthorizationDecisionEvent(
    string ClientId,
    string? Subject,
    string Flow,
    bool Approved,
    DateTimeOffset OccurredAt);

/// <summary>Raised when a client is registered (<c>created</c>), <c>updated</c> or <c>deleted</c> through DCR.</summary>
public sealed record ClientRegistrationChangedEvent(
    string ClientId,
    string Change,
    DateTimeOffset OccurredAt);
