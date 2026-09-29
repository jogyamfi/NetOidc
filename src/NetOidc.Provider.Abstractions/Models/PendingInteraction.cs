namespace NetOidc.Provider.Abstractions.Models;

/// <summary>What the End-User was sent to do before the authorization request can continue.</summary>
public enum InteractionKind
{
    Login,
    Consent,
}

/// <summary>
/// An authorization request that was suspended for login or consent. Its id travels in the
/// return URL as <c>interaction</c>; when the request resumes, the provider knows the prompt
/// (e.g. <c>prompt=login</c>) was satisfied by an interaction that happened after
/// <see cref="CreatedAt"/>.
/// </summary>
public sealed class PendingInteraction
{
    public required string InteractionId { get; init; }
    public required string ClientId { get; init; }
    public required InteractionKind Kind { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}
