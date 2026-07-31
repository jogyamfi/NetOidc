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
