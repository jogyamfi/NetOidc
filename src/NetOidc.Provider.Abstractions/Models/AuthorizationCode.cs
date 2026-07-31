namespace NetOidc.Provider.Abstractions.Models;

/// <summary>One-time-use authorization code issued by the authorization endpoint.</summary>
public sealed class AuthorizationCode
{
    public required string Code { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Subject { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
    public string? Nonce { get; init; }
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
    public required DateTimeOffset AuthTime { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}
