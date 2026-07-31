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

        // Advertise subject_types_supported based on configuration
        var subjectTypes = opts.SubjectType == "pairwise"
            ? new List<string> { "pairwise", "public" }
            : new List<string> { "public" };

        return new DiscoveryDocument
        {
            Issuer = issuer,
            AuthorizationEndpoint = Abs(opts.AuthorizationEndpoint),
            TokenEndpoint = Abs(opts.TokenEndpoint),
            UserInfoEndpoint = Abs(opts.UserInfoEndpoint),
            IntrospectionEndpoint = Abs(opts.IntrospectionEndpoint),
            RevocationEndpoint = Abs(opts.RevocationEndpoint),
            JwksUri = Abs(opts.JwksEndpoint),
            ResponseTypesSupported =
            [
                "code",
                "token",
                "id_token",
                "code token",
                "code id_token",
                "code id_token token",
                "id_token token",
            ],
            GrantTypesSupported =
            [
                "authorization_code",
                "implicit",
                "hybrid",
                "client_credentials",
                "refresh_token",
            ],
            SubjectTypesSupported = subjectTypes,
            IdTokenSigningAlgValuesSupported = ["RS256"],
            TokenEndpointAuthMethodsSupported = ["client_secret_basic", "client_secret_post"],
            IntrospectionEndpointAuthMethodsSupported = ["client_secret_basic", "client_secret_post"],
            RevocationEndpointAuthMethodsSupported = ["client_secret_basic", "client_secret_post"],
            CodeChallengeMethodsSupported = ["S256", "plain"],
            ScopesSupported = opts.Scopes.Select(s => s.Name).ToList(),
            ResponseModesSupported = ["query", "fragment", "form_post"],
            ClaimsParameterSupported = true,
            AuthorizationResponseIssParameterSupported = opts.IssuerIdentificationEnabled,
            EndSessionEndpoint = opts.LogoutEnabled ? Abs(opts.EndSessionEndpoint) : null,
            RegistrationEndpoint = opts.DcrEnabled ? Abs(opts.RegistrationEndpoint) : null,
            BackChannelLogoutSupported = opts.BackChannelLogoutEnabled,
            BackChannelLogoutSessionSupported = opts.BackChannelLogoutEnabled,
        };
    }

    /// <summary>Returns the JSON Web Key Set containing all active public keys.</summary>
    public object BuildJwks() => new { keys = new[] { _keyProvider.GetPublicJwk() } };
}
