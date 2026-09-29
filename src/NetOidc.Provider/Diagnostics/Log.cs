using Microsoft.Extensions.Logging;

namespace NetOidc.Provider.Diagnostics;

/// <summary>
/// Structured log messages. Messages carry client ids, grant types and error codes — never
/// tokens, secrets, codes or End-User identifiers.
/// </summary>
internal static partial class Log
{
    [LoggerMessage(1001, LogLevel.Warning, "Client authentication failed at {Endpoint} for client {ClientId}: {Reason}")]
    public static partial void ClientAuthenticationFailed(ILogger logger, string endpoint, string? clientId, string reason);

    [LoggerMessage(1002, LogLevel.Information, "Issued {GrantType} tokens to client {ClientId}")]
    public static partial void TokensIssued(ILogger logger, string clientId, string grantType);

    [LoggerMessage(1003, LogLevel.Warning, "Token request ({GrantType}) from client {ClientId} failed: {Error} {Description}")]
    public static partial void TokenRequestFailed(ILogger logger, string? clientId, string grantType, string error, string? description);

    [LoggerMessage(1004, LogLevel.Information, "Authorization for client {ClientId} completed")]
    public static partial void AuthorizationCompleted(ILogger logger, string clientId);

    [LoggerMessage(1005, LogLevel.Warning, "Authorization for client {ClientId} failed: {Error} {Description}")]
    public static partial void AuthorizationFailed(ILogger logger, string? clientId, string error, string? description);

    [LoggerMessage(1006, LogLevel.Information, "Authorization for client {ClientId} suspended for {Interaction}")]
    public static partial void AuthorizationSuspended(ILogger logger, string clientId, string interaction);

    [LoggerMessage(1007, LogLevel.Debug, "Introspection by client {ClientId}: active={Active}")]
    public static partial void Introspected(ILogger logger, string clientId, bool active);

    [LoggerMessage(1008, LogLevel.Information, "Revocation requested by client {ClientId}")]
    public static partial void RevocationRequested(ILogger logger, string clientId);

    [LoggerMessage(1009, LogLevel.Information, "UserInfo request rejected: {Error}")]
    public static partial void UserInfoRejected(ILogger logger, string error);

    [LoggerMessage(1010, LogLevel.Information, "Session ended; {ClientCount} client(s) notified")]
    public static partial void LoggedOut(ILogger logger, int clientCount);

    [LoggerMessage(1011, LogLevel.Information, "{Flow} request for client {ClientId} {Decision}")]
    public static partial void AuthorizationDecision(ILogger logger, string flow, string clientId, string decision);

    [LoggerMessage(1012, LogLevel.Information, "Dynamic client {ClientId} {Change}")]
    public static partial void ClientRegistrationChanged(ILogger logger, string clientId, string change);

    [LoggerMessage(1013, LogLevel.Information, "Pushed authorization request stored for client {ClientId}")]
    public static partial void PushedAuthorizationStored(ILogger logger, string clientId);
}
