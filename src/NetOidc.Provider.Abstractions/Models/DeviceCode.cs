namespace NetOidc.Provider.Abstractions.Models;

/// <summary>
/// Represents a device authorization request (RFC 8628 §3.2).
/// Stored while the device polls and the user completes authorization on a secondary device.
/// </summary>
public sealed class DeviceCode
{
    public required string DeviceCodeValue { get; init; }

    public required string UserCode { get; init; }

    public required string ClientId { get; init; }

    public IReadOnlyList<string> RequestedScopes { get; init; } = [];

    /// <summary>Subject identifier set when the user approves the request. Null while pending.</summary>
    public string? Subject { get; set; }

    /// <summary>Granted scopes after user consent. Empty while pending.</summary>
    public IReadOnlyList<string> GrantedScopes { get; set; } = [];

    /// <summary>
    /// Current status of the device authorization.
    /// </summary>
    public DeviceCodeStatus Status { get; set; } = DeviceCodeStatus.Pending;

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Tracks the last time the client polled to enforce the minimum interval.</summary>
    public DateTimeOffset? LastPolledAt { get; set; }
}

public enum DeviceCodeStatus
{
    Pending,
    Approved,
    Denied,
}
