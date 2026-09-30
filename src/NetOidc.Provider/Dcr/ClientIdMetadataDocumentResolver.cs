using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Adapters;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Dcr;

/// <summary>
/// Resolves clients identified by the URL of their Client ID Metadata Document
/// (draft-ietf-oauth-client-id-metadata-document): the provider fetches the document from the
/// <c>client_id</c> URL, validates it, and treats it as the client's registration.
/// </summary>
internal sealed class ClientIdMetadataDocumentResolver : IClientResolver
{
    private static readonly TimeSpan MinCache = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MaxCache = TimeSpan.FromDays(1);

    private readonly IOptions<ProviderOptions> _options;
    private readonly SafeHttpFetcher _fetcher;
    private readonly ILogger<ClientIdMetadataDocumentResolver> _logger;

    public ClientIdMetadataDocumentResolver(
        IOptions<ProviderOptions> options, SafeHttpFetcher fetcher, ILogger<ClientIdMetadataDocumentResolver> logger)
    {
        _options = options;
        _fetcher = fetcher;
        _logger = logger;
    }

    public async Task<ResolvedClient?> ResolveAsync(string clientId, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.ClientIdMetadataDocumentEnabled)
            return null;

        var uri = new Uri(clientId);
        // The draft requires a path component; a bare origin is not a metadata document URL.
        if (uri.AbsolutePath is "/" or "" || !string.IsNullOrEmpty(uri.Query))
            return Reject(clientId, "client_id URL must have a path and no query");
        if (opts.ClientIdMetadataDocumentAllowedHosts.Count > 0 &&
            !opts.ClientIdMetadataDocumentAllowedHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
            return Reject(clientId, "host is not allowed");

        var document = await _fetcher.GetAsync(clientId, opts.ClientIdMetadataDocumentMaxBytes, "application/json", ct);
        if (document is null)
            return Reject(clientId, "document could not be fetched");

        JsonElement root;
        try { root = JsonDocument.Parse(document.Content).RootElement.Clone(); }
        catch (JsonException) { return Reject(clientId, "document is not JSON"); }
        if (root.ValueKind != JsonValueKind.Object)
            return Reject(clientId, "document is not a JSON object");

        if (String(root, "client_id") != clientId)
            return Reject(clientId, "client_id in the document does not match its URL");
        if (root.TryGetProperty("client_secret", out _) || root.TryGetProperty("client_secret_expires_at", out _))
            return Reject(clientId, "documents must not contain client secrets");

        var redirectUris = Strings(root, "redirect_uris");
        if (redirectUris.Count == 0)
            return Reject(clientId, "redirect_uris is required");
        foreach (var redirect in redirectUris)
            if (ClientMetadataValidator.ValidateRedirectUri(redirect) is { } error)
                return Reject(clientId, error);

        var authMethod = String(root, "token_endpoint_auth_method") ?? "none";
        string? jwks = null;
        switch (authMethod)
        {
            case "none":
                break;
            case "private_key_jwt":
                if (root.TryGetProperty("jwks", out var inline) && inline.ValueKind == JsonValueKind.Object)
                    jwks = inline.GetRawText();
                else if (String(root, "jwks_uri") is { } jwksUri &&
                         await _fetcher.GetAsync(jwksUri, opts.ClientIdMetadataDocumentMaxBytes, "application/json", ct) is { } fetched)
                    jwks = fetched.Content;
                if (jwks is null)
                    return Reject(clientId, "private_key_jwt requires jwks or a reachable jwks_uri");
                break;
            default:
                return Reject(clientId, $"token_endpoint_auth_method '{authMethod}' is not supported");
        }

        var grantTypes = Strings(root, "grant_types");
        if (grantTypes.Count == 0) grantTypes = ["authorization_code"];
        if (grantTypes.Any(g => g is not ("authorization_code" or "refresh_token")))
            return Reject(clientId, "only authorization_code and refresh_token grants are allowed");

        var registeredScopes = opts.Scopes.Select(s => s.Name).ToList();
        var requestedScopes = (String(root, "scope") ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var allowedScopes = requestedScopes.Length == 0
            ? registeredScopes
            : requestedScopes.Where(registeredScopes.Contains).ToList();

        var client = new Client
        {
            ClientId = clientId,
            TokenEndpointAuthMethod = authMethod,
            JwksJson = jwks,
            RedirectUris = redirectUris,
            PostLogoutRedirectUris = Strings(root, "post_logout_redirect_uris")
                .Where(u => ClientMetadataValidator.ValidateRedirectUri(u) is null).ToList(),
            AllowedGrantTypes = grantTypes,
            ResponseTypes = ["code"],
            AllowedScopes = allowedScopes,
            ClientName = String(root, "client_name"),
            ClientUri = String(root, "client_uri"),
            LogoUri = String(root, "logo_uri"),
            PolicyUri = String(root, "policy_uri"),
            TosUri = String(root, "tos_uri"),
            // Unknown third party: always PKCE, always ask the End-User.
            RequirePkce = true,
            RequireConsent = true,
            IsDynamic = true,
        };

        var cacheFor = document.MaxAge ?? TimeSpan.FromSeconds(opts.ClientIdMetadataDocumentCacheSeconds);
        return new ResolvedClient(client, cacheFor < MinCache ? MinCache : cacheFor > MaxCache ? MaxCache : cacheFor);
    }

    private ResolvedClient? Reject(string clientId, string reason)
    {
        _logger.LogInformation("Client ID Metadata Document {ClientId} rejected: {Reason}", clientId, reason);
        return null;
    }

    private static string? String(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static List<string> Strings(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
            : [];
}
