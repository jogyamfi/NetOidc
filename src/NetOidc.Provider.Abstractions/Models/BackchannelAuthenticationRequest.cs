namespace NetOidc.Provider.Abstractions.Models;

/// <summary>
/// Represents a CIBA backchannel authentication request
/// (OpenID Connect Client-Initiated Backchannel Authentication Flow Core 1.0 §7.1).
/// Supports poll mode: the client polls the token endpoint using <c>auth_req_id</c>.
/// </summary>
public sealed class BackchannelAuthenticationRequest
{
    public required string AuthReqId { get; init; }

    public required string ClientId { get; init; }

    /// <summary>Hint used to identify the user for out-of-band authentication.</summary>
    public string? LoginHint { get; init; }

    /// <summary>Hint identifying the user by a previously issued id_token.</summary>
    public string? IdTokenHint { get; init; }

    public IReadOnlyList<string> RequestedScopes { get; init; } = [];

    /// <summary>Subject identifier set when out-of-band authentication succeeds. Null while pending.</summary>
    public string? Subject { get; set; }

    /// <summary>Granted scopes after out-of-band consent. Empty while pending.</summary>
    public IReadOnlyList<string> GrantedScopes { get; set; } = [];

    /// <summary>
    /// Current status of the backchannel authentication request.
    /// </summary>
    public BackchannelAuthenticationStatus Status { get; set; } = BackchannelAuthenticationStatus.Pending;

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
