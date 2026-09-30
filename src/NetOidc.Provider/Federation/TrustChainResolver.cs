using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Federation;

/// <summary>A verified trust chain and the leaf metadata after all policies were applied.</summary>
/// <param name="ImmediateSuperior">The superior that issued the leaf's subordinate statement.</param>
/// <param name="LeafConfiguration">The leaf's (self-signed) entity configuration.</param>
internal sealed record TrustChain(
    string EntityId,
    string TrustAnchorId,
    string ImmediateSuperior,
    JsonObject Metadata,
    EntityStatement LeafConfiguration,
    DateTimeOffset ExpiresAt);

/// <summary>
/// Resolves and verifies OpenID Federation 1.1 trust chains (§10): from the leaf's entity
/// configuration through its <c>authority_hints</c> to a configured trust anchor, checking every
/// signature and key hand-over, then applying the chain's metadata and metadata policies.
/// </summary>
internal sealed class TrustChainResolver
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly SafeHttpFetcher _fetcher;
    private readonly ILogger<TrustChainResolver> _logger;

    public TrustChainResolver(IOptions<ProviderOptions> options, SafeHttpFetcher fetcher, ILogger<TrustChainResolver> logger)
    {
        _options = options;
        _fetcher = fetcher;
        _logger = logger;
    }

    /// <summary>
    /// Resolves a chain for <paramref name="entityId"/> and returns its effective metadata for
    /// <paramref name="entityType"/> (e.g. <c>openid_relying_party</c>). A leaf entity
    /// configuration already in hand (explicit registration) can be supplied.
    /// </summary>
    public async Task<(TrustChain? Chain, string? Error)> ResolveAsync(
        string entityId, string entityType, EntityStatement? leafConfiguration, CancellationToken ct)
    {
        var opts = _options.Value;
        if (opts.FederationTrustAnchors.Count == 0)
            return (null, "no trust anchors are configured");

        var leaf = leafConfiguration ?? await FetchConfigurationAsync(entityId, ct);
        if (leaf is null)
            return Fail(entityId, "entity configuration could not be fetched");
        if (leaf.Issuer != entityId || leaf.Subject != entityId)
            return Fail(entityId, "entity configuration iss/sub must equal the entity id");
        if (!await leaf.VerifyAsync(leaf.Jwks))
            return Fail(entityId, "entity configuration is not validly self-signed");

        var path = await FindPathAsync(leaf, depth: 1, [entityId], ct);
        if (path is null)
            return Fail(entityId, "no valid trust chain to a configured trust anchor");

        // Effective metadata: the leaf's own, overridden by its immediate superior's `metadata`,
        // then constrained by every superior's policy from the trust anchor downwards (§6.1.4).
        if (leaf.Metadata(entityType)?.DeepClone() is not JsonObject metadata)
            return Fail(entityId, $"entity has no {entityType} metadata");
        if (path.Statements[0].Metadata(entityType) is { } overrides)
            foreach (var (name, value) in overrides)
                metadata[name] = value?.DeepClone();
        foreach (var statement in Enumerable.Reverse(path.Statements))
        {
            if (statement.MetadataPolicy(entityType) is { } policy && MetadataPolicy.Apply(metadata, policy) is { } error)
                return Fail(entityId, $"metadata policy from {statement.Issuer}: {error}");
        }

        var expiresAt = path.Statements.Select(s => s.ExpiresAt).Append(leaf.ExpiresAt)
            .Where(e => e is not null).Select(e => e!.Value).DefaultIfEmpty(DateTimeOffset.UtcNow).Min();

        return (new TrustChain(entityId, path.TrustAnchor, path.Statements[0].Issuer!, metadata, leaf, expiresAt), null);
    }

    private sealed record ChainPath(List<EntityStatement> Statements, string TrustAnchor);

    /// <summary>
    /// Depth-first search through <paramref name="subject"/>'s authority hints. Returns the
    /// subordinate statements from the subject upwards and the trust anchor reached.
    /// </summary>
    private async Task<ChainPath?> FindPathAsync(
        EntityStatement subject, int depth, HashSet<string> visited, CancellationToken ct)
    {
        var opts = _options.Value;
        if (depth > opts.FederationMaxChainLength) return null;

        foreach (var superiorId in subject.AuthorityHints)
        {
            if (!visited.Add(superiorId)) continue;   // loops are never valid chains

            var isAnchor = opts.FederationTrustAnchors.TryGetValue(superiorId, out var anchorJwksJson);
            var superior = await FetchConfigurationAsync(superiorId, ct);
            if (superior is null || superior.Issuer != superiorId || superior.Subject != superiorId)
                continue;

            // A trust anchor is verified with the configured keys, never its self-published ones.
            var superiorKeys = isAnchor ? EntityStatement.TryJwks(anchorJwksJson!) : superior.Jwks;
            if (!await superior.VerifyAsync(superiorKeys) || superior.FetchEndpoint is not { } fetchEndpoint)
                continue;

            var fetched = await _fetcher.GetAsync(
                QueryHelpers.AddQueryString(fetchEndpoint, "sub", subject.Subject!),
                opts.FederationMaxStatementBytes, EntityStatement.MediaType, ct);
            if (fetched is null || EntityStatement.Parse(fetched.Content.Trim()) is not { } statement)
                continue;

            // The superior vouches for the subject: its statement is signed with the superior's
            // keys and carries the subject's keys, which must verify the subject's configuration.
            if (statement.Issuer != superiorId || statement.Subject != subject.Subject ||
                !await statement.VerifyAsync(superiorKeys) || !await subject.VerifyAsync(statement.Jwks))
                continue;

            if (isAnchor)
                return new ChainPath([statement], superiorId);

            if (await FindPathAsync(superior, depth + 1, visited, ct) is { } rest)
                return new ChainPath([statement, .. rest.Statements], rest.TrustAnchor);
        }
        return null;
    }

    private async Task<EntityStatement?> FetchConfigurationAsync(string entityId, CancellationToken ct)
    {
        var url = entityId.TrimEnd('/') + "/.well-known/openid-federation";
        var fetched = await _fetcher.GetAsync(url, _options.Value.FederationMaxStatementBytes, EntityStatement.MediaType, ct);
        return fetched is null ? null : EntityStatement.Parse(fetched.Content.Trim());
    }

    private (TrustChain?, string?) Fail(string entityId, string reason)
    {
        _logger.LogInformation("Trust chain for {EntityId} rejected: {Reason}", entityId, reason);
        return (null, reason);
    }
}
