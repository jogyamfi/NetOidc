namespace NetOidc.Provider.Abstractions.Models;

/// <summary>A pushed authorization request record (RFC 9126).</summary>
public sealed class PushedAuthorizationRequest
{
    /// <summary>The <c>urn:ietf:params:oauth:request_uri:{token}</c> URI returned to the client.</summary>
    public required string RequestUri { get; init; }

    public required string ClientId { get; init; }

    /// <summary>JSON-serialized dictionary of authorization request parameters.</summary>
    public required string ParametersJson { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }
}
