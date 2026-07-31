using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;

namespace NetOidc.Provider.Discovery;

/// <summary>
/// Handles <c>GET /.well-known/client_id_metadata/{clientId}</c>.
/// Returns the publicly-visible registration metadata for a known client.
/// This implements the Client ID Metadata Document draft (draft-ietf-oauth-client-id-metadata-document).
/// </summary>
public sealed class ClientIdMetadataEndpointHandler
{
    private readonly IClientStore _clientStore;
    private readonly IOptions<ProviderOptions> _options;

    public ClientIdMetadataEndpointHandler(IClientStore clientStore, IOptions<ProviderOptions> options)
    {
        _clientStore = clientStore;
        _options = options;
    }

    public async Task<IResult> HandleAsync(string clientId, CancellationToken ct)
    {
        if (!_options.Value.ClientIdMetadataDocumentEnabled)
            return Results.Json(OAuthError.InvalidRequest("Client ID Metadata Document is not enabled"), statusCode: 404);

        var client = await _clientStore.FindClientAsync(clientId, ct);
        if (client is null)
            return Results.NotFound();

        return Results.Json(BuildMetadata(client));
    }

    private static object BuildMetadata(Client client)
    {
        // Expose only public registration fields — never secrets or internal hashes
        var meta = new Dictionary<string, object>
        {
            ["client_id"] = client.ClientId,
            ["grant_types"] = client.AllowedGrantTypes,
            ["scope"] = string.Join(" ", client.AllowedScopes),
            ["redirect_uris"] = client.RedirectUris,
            ["token_endpoint_auth_method"] = client.TokenEndpointAuthMethod,
            ["require_pkce"] = client.RequirePkce,
        };

        if (!string.IsNullOrEmpty(client.ClientName)) meta["client_name"] = client.ClientName;
        if (!string.IsNullOrEmpty(client.ClientUri)) meta["client_uri"] = client.ClientUri;
        if (!string.IsNullOrEmpty(client.LogoUri)) meta["logo_uri"] = client.LogoUri;
        if (client.Contacts.Count > 0) meta["contacts"] = client.Contacts;
        if (client.PostLogoutRedirectUris.Count > 0)
            meta["post_logout_redirect_uris"] = client.PostLogoutRedirectUris;
        if (!string.IsNullOrEmpty(client.JwksJson)) meta["jwks"] = client.JwksJson;

        return meta;
    }
}
