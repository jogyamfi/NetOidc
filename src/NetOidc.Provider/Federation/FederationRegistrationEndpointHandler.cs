using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Adapters;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Federation;

/// <summary>
/// OpenID Federation explicit registration (§12.2): the RP POSTs its entity configuration
/// (<c>application/entity-statement+jwt</c>, with <c>aud</c> set to this provider); the provider
/// resolves the RP's trust chain, registers the client until the chain expires, and answers with
/// a signed registration response.
/// </summary>
public sealed class FederationRegistrationEndpointHandler
{
    private const int MaxBodyBytes = 65536;

    private readonly IOptions<ProviderOptions> _options;
    private readonly TrustChainResolver _chains;
    private readonly FederationClientFactory _factory;
    private readonly FederationService _federation;
    private readonly IAdapter<Client> _clientCache;
    private readonly IDynamicClientStore _registered;

    public FederationRegistrationEndpointHandler(
        IOptions<ProviderOptions> options, TrustChainResolver chains, FederationClientFactory factory,
        FederationService federation, IAdapter<Client> clientCache, IDynamicClientStore registered)
    {
        _options = options;
        _chains = chains;
        _factory = factory;
        _federation = federation;
        _clientCache = clientCache;
        _registered = registered;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.FederationEnabled || !opts.FederationExplicitRegistrationEnabled)
            return Results.NotFound();

        if (!string.Equals(context.Request.ContentType?.Split(';')[0].Trim(), EntityStatement.MediaType, StringComparison.OrdinalIgnoreCase))
            return Error($"Content-Type must be {EntityStatement.MediaType}");
        if (context.Request.ContentLength > MaxBodyBytes)
            return Error("Request is too large");

        string body;
        using (var reader = new StreamReader(context.Request.Body))
        {
            var buffer = new char[MaxBodyBytes + 1];
            var read = await reader.ReadBlockAsync(buffer, ct);
            if (read > MaxBodyBytes) return Error("Request is too large");
            body = new string(buffer, 0, read).Trim();
        }

        if (EntityStatement.Parse(body) is not { Subject: { } entityId } leaf)
            return Error("The request is not an entity statement");

        // The request is addressed to this provider only (§12.2.1).
        var issuer = opts.Issuer.TrimEnd('/');
        var audience = leaf.Payload["aud"];
        var addressedHere = audience is System.Text.Json.Nodes.JsonArray list
            ? list.Any(a => a.AsString() == issuer)
            : audience.AsString() == issuer;
        if (!addressedHere)
            return Error("aud must be this provider's entity identifier");

        // A client registered by other means (static or DCR) is never replaced. The registered
        // store is used directly: resolving through IClientStore would auto-register the entity.
        if (await _registered.FindClientAsync(entityId, ct) is not null)
            return Error("The entity is already registered");

        var (chain, chainError) = await _chains.ResolveAsync(entityId, "openid_relying_party", leaf, ct);
        if (chain is null)
            return Error(chainError ?? "Trust chain could not be resolved");

        var (client, clientError) = await _factory.CreateAsync(chain, automatic: false, ct);
        if (client is null)
            return Error(clientError!, "invalid_client_metadata");

        var lifetime = chain.ExpiresAt - DateTimeOffset.UtcNow;
        if (lifetime <= TimeSpan.Zero)
            return Error("The trust chain has expired");
        await _clientCache.StoreAsync(ResolvingClientStore.CachePrefix + entityId, client, lifetime, ct);

        return Results.Content(_federation.BuildRegistrationResponse(chain, client),
            "application/explicit-registration-response+jwt");
    }

    private static IResult Error(string description, string error = "invalid_request") =>
        Results.BadRequest(new OAuthError(error, description));
}
