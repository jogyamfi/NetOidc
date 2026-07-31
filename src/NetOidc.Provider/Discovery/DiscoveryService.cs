using Microsoft.Extensions.Options;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Discovery;

/// <summary>Builds the OIDC discovery document and JWKS response from provider configuration.</summary>
public sealed class DiscoveryService
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly SigningKeyProvider _keyProvider;

    public DiscoveryService(IOptions<ProviderOptions> options, SigningKeyProvider keyProvider)
    {
        _options = options;
        _keyProvider = keyProvider;
    }

    public DiscoveryDocument BuildDocument()
    {
        var opts = _options.Value;
        var issuer = opts.Issuer.TrimEnd('/');
        string Abs(string path) => issuer + path;

        return new DiscoveryDocument
        {
            Issuer = issuer,
            AuthorizationEndpoint = Abs(opts.AuthorizationEndpoint),
            TokenEndpoint = Abs(opts.TokenEndpoint),
            UserInfoEndpoint = Abs(opts.UserInfoEndpoint),
            JwksUri = Abs(opts.JwksEndpoint),
            ResponseTypesSupported = ["code"],
            GrantTypesSupported = ["authorization_code", "refresh_token"],
            SubjectTypesSupported = ["public"],
            IdTokenSigningAlgValuesSupported = ["RS256"],
            TokenEndpointAuthMethodsSupported = ["client_secret_basic", "client_secret_post"],
            CodeChallengeMethodsSupported = ["S256", "plain"],
            ScopesSupported = opts.Scopes.Select(s => s.Name).ToList(),
            ResponseModesSupported = ["query", "fragment", "form_post"],
        };
    }

    /// <summary>Returns the JSON Web Key Set containing all active public keys.</summary>
    public object BuildJwks() => new { keys = new[] { _keyProvider.GetPublicJwk() } };
}
