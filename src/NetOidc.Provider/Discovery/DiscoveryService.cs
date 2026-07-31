using Microsoft.Extensions.Options;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Discovery;

/// <summary>Builds the OIDC discovery document and JWKS response from provider configuration.</summary>
public sealed class DiscoveryService
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly SigningKeyProvider _keyProvider;
    private readonly EncryptionKeyProvider _encryptionKeyProvider;

    public DiscoveryService(
        IOptions<ProviderOptions> options,
        SigningKeyProvider keyProvider,
        EncryptionKeyProvider encryptionKeyProvider)
    {
        _options = options;
        _keyProvider = keyProvider;
        _encryptionKeyProvider = encryptionKeyProvider;
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

        var responseModes = new List<string> { "query", "fragment", "form_post" };
        if (opts.JarmEnabled)
            responseModes.AddRange(["query.jwt", "fragment.jwt", "form_post.jwt", "jwt"]);

        var grantTypes = new List<string>
        {
            "authorization_code",
            "implicit",
            "hybrid",
            "client_credentials",
            "refresh_token",
        };
        if (opts.TokenExchangeEnabled)
            grantTypes.Add("urn:ietf:params:oauth:grant-type:token-exchange");
        if (opts.JwtBearerGrantEnabled)
            grantTypes.Add("urn:ietf:params:oauth:grant-type:jwt-bearer");

        // ── Phase 5: build token_endpoint_auth_methods_supported ────────────────
        var tokenAuthMethods = new List<string>
        {
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "client_secret_jwt",
        };
        if (opts.MtlsEnabled)
        {
            tokenAuthMethods.Add("tls_client_auth");
            tokenAuthMethods.Add("self_signed_tls_client_auth");
        }

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
            GrantTypesSupported = grantTypes,
            SubjectTypesSupported = subjectTypes,
            IdTokenSigningAlgValuesSupported = ["RS256"],
            TokenEndpointAuthMethodsSupported = tokenAuthMethods,
            IntrospectionEndpointAuthMethodsSupported = tokenAuthMethods,
            RevocationEndpointAuthMethodsSupported = tokenAuthMethods,
            CodeChallengeMethodsSupported = ["S256", "plain"],
            ScopesSupported = opts.Scopes.Select(s => s.Name).ToList(),
            ResponseModesSupported = responseModes,
            ClaimsParameterSupported = true,
            AuthorizationResponseIssParameterSupported = opts.IssuerIdentificationEnabled,
            EndSessionEndpoint = opts.LogoutEnabled ? Abs(opts.EndSessionEndpoint) : null,
            RegistrationEndpoint = opts.DcrEnabled ? Abs(opts.RegistrationEndpoint) : null,
            BackChannelLogoutSupported = opts.BackChannelLogoutEnabled,
            BackChannelLogoutSessionSupported = opts.BackChannelLogoutEnabled,

            // ── Phase 4 ──────────────────────────────────────────────────────
            PushedAuthorizationRequestEndpoint = opts.PushedAuthorizationEnabled
                ? Abs(opts.PushedAuthorizationEndpoint) : null,
            RequirePushedAuthorizationRequests = opts.RequirePushedAuthorization,
            RequestParameterSupported = opts.JarEnabled,
            RequestObjectSigningAlgValuesSupported = opts.JarEnabled
                ? ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
                : null,
            RequestObjectEncryptionAlgValuesSupported = opts.JarEnabled
                ? ["RSA-OAEP", "RSA-OAEP-256"]
                : null,
            RequestObjectEncryptionEncValuesSupported = opts.JarEnabled
                ? ["A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM"]
                : null,
            AuthorizationSigningAlgValuesSupported = opts.JarmEnabled
                ? ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
                : null,
            ResourceIndicatorsSupported = opts.ResourceIndicatorsEnabled,
            AuthorizationDetailsTypesSupported = opts.RichAuthorizationRequestsEnabled &&
                opts.AuthorizationDetailsTypesSupported.Count > 0
                ? opts.AuthorizationDetailsTypesSupported.ToList()
                : null,
            IdTokenEncryptionAlgValuesSupported =
                ["RSA-OAEP", "RSA-OAEP-256"],
            IdTokenEncryptionEncValuesSupported =
                ["A128CBC-HS256", "A256CBC-HS512", "A128GCM", "A256GCM"],

            // ── Phase 5 ──────────────────────────────────────────────────────
            DPoPSigningAlgValuesSupported = opts.DPoPEnabled
                ? ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                   "ES256", "ES384", "ES512"]
                : null,
            TlsClientCertificateBoundAccessTokens = opts.MtlsEnabled,
        };
    }

    /// <summary>Returns the JSON Web Key Set containing all active public keys.</summary>
    public object BuildJwks() => new
    {
        keys = new object[]
        {
            _keyProvider.GetPublicJwk(),
            _encryptionKeyProvider.GetPublicJwk(),
        }
    };
}
