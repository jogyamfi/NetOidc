namespace NetOidc.Provider.Abstractions.Models;

/// <summary>
/// Represents a CIBA backchannel authentication request
/// (OpenID Connect Client-Initiated Backchannel Authentication Flow Core 1.0 §7.1).
/// </summary>
public sealed class BackchannelAuthenticationRequest
{
    public required string AuthReqId { get; init; }
    public required string ClientId { get; init; }

    /// <summary>Token delivery mode for this request: <c>poll</c>, <c>ping</c> or <c>push</c>.</summary>
    public string DeliveryMode { get; init; } = "poll";

    /// <summary>Bearer token the OP presents to the client notification endpoint (ping/push).</summary>
    public string? ClientNotificationToken { get; init; }

    /// <summary>Hint used to identify the user for out-of-band authentication.</summary>
    public string? LoginHint { get; init; }

    /// <summary>Opaque login hint token supplied by the client.</summary>
    public string? LoginHintToken { get; init; }

    /// <summary>A previously issued id_token identifying the user (already validated).</summary>
    public string? IdTokenHint { get; init; }

    /// <summary><c>sub</c> of <see cref="IdTokenHint"/> as issued to the client (public or pairwise).</summary>
    public string? HintSubject { get; init; }

    /// <summary>Secret the user supplies to the client to authorize the request (CIBA §7.1).</summary>
    public string? UserCode { get; init; }

    /// <summary>Requested <c>acr_values</c>, space separated.</summary>
    public string? AcrValues { get; init; }

    public IReadOnlyList<string> RequestedScopes { get; init; } = [];

    /// <summary>Local subject identifier set when out-of-band authentication succeeds. Null while pending.</summary>
    public string? Subject { get; set; }

    /// <summary>Granted scopes after out-of-band consent. Empty while pending.</summary>
    public IReadOnlyList<string> GrantedScopes { get; set; } = [];

    /// <summary>Current status of the backchannel authentication request.</summary>
    public BackchannelAuthenticationStatus Status { get; set; } = BackchannelAuthenticationStatus.Pending;

    /// <summary>When the End-User authenticated out of band (<c>auth_time</c>).</summary>
    public DateTimeOffset? AuthTime { get; set; }

    /// <summary>Authentication context the out-of-band authentication achieved.</summary>
    public string? Acr { get; set; }

    /// <summary>Optional human-readable message to display to the user during out-of-band auth.</summary>
    public string? BindingMessage { get; init; }

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Tracks the last time the client polled.</summary>
    public DateTimeOffset? LastPolledAt { get; set; }
}

public enum BackchannelAuthenticationStatus
{
    Pending,
    Approved,
    Denied,
}
