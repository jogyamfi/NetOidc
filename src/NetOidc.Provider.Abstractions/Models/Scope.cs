namespace NetOidc.Provider.Abstractions.Models;

public sealed class Scope
{
    public required string Name { get; init; }

    public string? Description { get; init; }

    /// <summary>
    /// Claims this scope releases. Leave empty for the standard OIDC scopes (<c>profile</c>,
    /// <c>email</c>, <c>address</c>, <c>phone</c>), whose claims are defined by OIDC Core §5.4.
    /// </summary>
    public IReadOnlyList<string> Claims { get; init; } = [];
}
