namespace NetOidc.Provider.Abstractions.Models;

public sealed class Scope
{
    public required string Name { get; init; }

    public string? Description { get; init; }
}
