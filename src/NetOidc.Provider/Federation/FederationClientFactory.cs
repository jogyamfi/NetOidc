using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Dcr;
using NetOidc.Provider.Http;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Federation;

/// <summary>
/// Turns the effective <c>openid_relying_party</c> metadata of a verified trust chain into a
/// <see cref="Client"/>. Shared by automatic and explicit registration.
/// </summary>
public sealed class FederationClientFactory
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly SafeHttpFetcher _fetcher;

    public FederationClientFactory(IOptions<ProviderOptions> options, SafeHttpFetcher fetcher)
    {
        _options = options;
        _fetcher = fetcher;
    }

    /// <summary>Returns the client, or an error description when the metadata is unacceptable.</summary>
    public async Task<(Client? Client, string? Error)> CreateAsync(TrustChain chain, bool automatic, CancellationToken ct)
    {
        var opts = _options.Value;
        var metadata = chain.Metadata;

        var redirectUris = Strings(metadata, "redirect_uris");
        if (redirectUris.Count == 0)
            return (null, "redirect_uris is required");
        foreach (var redirect in redirectUris)
            if (ClientMetadataValidator.ValidateRedirectUri(redirect) is { } error)
                return (null, error);

        // Federation RPs authenticate with keys they publish in their (policy-checked) metadata.
        var authMethod = metadata["token_endpoint_auth_method"].AsString() ?? "private_key_jwt";
        if (authMethod != "private_key_jwt")
            return (null, $"token_endpoint_auth_method '{authMethod}' is not supported for federation clients");

        string? jwks = null;
        if (metadata["jwks"] is JsonObject inline)
            jwks = inline.ToJsonString();
        else if (metadata["jwks_uri"].AsString() is { } jwksUri &&
                 await _fetcher.GetAsync(jwksUri, opts.FederationMaxStatementBytes, "application/json", ct) is { } fetched)
            jwks = fetched.Content;
        if (jwks is null || EntityStatement.TryJwks(jwks) is not { Keys.Count: > 0 })
            return (null, "jwks or a reachable jwks_uri is required");

        var grantTypes = Strings(metadata, "grant_types");
        if (grantTypes.Count == 0) grantTypes = ["authorization_code"];
        if (grantTypes.Any(g => g is not ("authorization_code" or "refresh_token")))
            return (null, "only authorization_code and refresh_token grants are allowed");

        var responseTypes = Strings(metadata, "response_types");
        if (responseTypes.Any(r => r != "code"))
            return (null, "only the code response type is allowed");

        foreach (var name in new[] { "request_object_signing_alg", "id_token_signed_response_alg" })
            if (metadata[name].AsString() is { } alg && !KeyRing.SupportedSigningAlgorithms.Contains(alg))
                return (null, $"{name} '{alg}' is not supported");

        var registeredScopes = opts.Scopes.Select(s => s.Name).ToList();
        var requestedScopes = (metadata["scope"].AsString() ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        // No scope (none requested, or a policy's subset_of removed them all) grants only openid,
        // never every registered scope.
        var allowedScopes = requestedScopes.Where(registeredScopes.Contains).DefaultIfEmpty("openid").Distinct().ToList();

        return (new Client
        {
            ClientId = chain.EntityId,
            TokenEndpointAuthMethod = authMethod,
            JwksJson = jwks,
            RedirectUris = redirectUris,
            PostLogoutRedirectUris = Strings(metadata, "post_logout_redirect_uris")
                .Where(u => ClientMetadataValidator.ValidateRedirectUri(u) is null).ToList(),
            AllowedGrantTypes = grantTypes,
            ResponseTypes = ["code"],
            AllowedScopes = allowedScopes,
            ClientName = metadata["client_name"].AsString(),
            ClientUri = metadata["client_uri"].AsString(),
            LogoUri = metadata["logo_uri"].AsString(),
            Contacts = Strings(metadata, "contacts"),
            RequestObjectSigningAlg = metadata["request_object_signing_alg"].AsString(),
            IdTokenSignedResponseAlg = metadata["id_token_signed_response_alg"].AsString(),
            // Automatic registration has no registration step, so every authorization request must
            // be a request object signed with the RP's keys (Federation 1.1 §12.1.1).
            RequireSignedRequestObject = automatic,
            RequirePkce = true,
            RequireConsent = true,
            IsDynamic = true,
            ClientIdIssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        }, null);
    }

    private static List<string> Strings(JsonObject metadata, string name) =>
        metadata[name] is JsonArray values
            ? values.OfType<JsonValue>().Select(v => v.TryGetValue<string>(out var s) ? s : null)
                .Where(s => s is not null).Select(s => s!).ToList()
            : [];
}
