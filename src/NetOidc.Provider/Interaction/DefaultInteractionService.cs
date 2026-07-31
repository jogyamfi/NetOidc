using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Interaction;

/// <summary>
/// Default implementation: trusts ASP.NET Core cookie authentication and auto-consents
/// to all scopes that are registered in <see cref="ProviderOptions.Scopes"/>.
/// </summary>
public sealed class DefaultInteractionService : IInteractionService
{
    private readonly IOptions<ProviderOptions> _options;

    public DefaultInteractionService(IOptions<ProviderOptions> options) => _options = options;

    public Task<InteractionResult?> GetInteractionResultAsync(
        HttpContext context,
        string clientId,
        IReadOnlyList<string> requestedScopes,
        CancellationToken ct = default)
    {
        if (context.User.Identity?.IsAuthenticated != true)
            return Task.FromResult<InteractionResult?>(null);

        var subject = context.User.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? context.User.FindFirstValue("sub");
        if (subject is null)
            return Task.FromResult<InteractionResult?>(null);

        var registeredScopes = _options.Value.Scopes.Select(s => s.Name).ToHashSet();
        var granted = requestedScopes.Where(s => registeredScopes.Contains(s)).ToList();

        return Task.FromResult<InteractionResult?>(new InteractionResult
        {
            Subject = subject,
            GrantedScopes = granted,
        });
    }
}
