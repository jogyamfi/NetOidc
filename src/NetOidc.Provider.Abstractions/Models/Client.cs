namespace NetOidc.Provider.Abstractions.Models;

/// <summary>Registered OAuth2/OIDC client (relying party).</summary>
public sealed class Client
{
    public required string ClientId { get; init; }

    public string? ClientSecret { get; init; }

    public IReadOnlyList<string> RedirectUris { get; init; } = [];

    public IReadOnlyList<string> AllowedGrantTypes { get; init; } = [];

    public IReadOnlyList<string> AllowedScopes { get; init; } = [];

    /// <summary>RFC 7591 token_endpoint_auth_method.</summary>
    public string TokenEndpointAuthMethod { get; init; } = "client_secret_basic";

    public bool RequirePkce { get; init; } = true;
}
