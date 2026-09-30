using Microsoft.Extensions.Options;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Discovery;

/// <summary>Builds the OIDC discovery document and JWKS response from provider configuration.</summary>
public sealed class DiscoveryService
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly KeyRing _keys;

    public DiscoveryService(
        IOptions<ProviderOptions> options,
        KeyRing keys)
    {
        _options = options;
        _keys = keys;
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

        // Response types the active profile accepts (see the FAPI checks in the authorization endpoint).
        var isFapi2 = opts.FapiProfile is FapiProfile.Fapi2Security or FapiProfile.Fapi2MessageSigning or FapiProfile.FapiCiba;
        var isFapi = isFapi2 || opts.FapiProfile == FapiProfile.Fapi1Advanced;
        List<string> responseTypes = opts.FapiProfile switch
        {
            FapiProfile.Fapi1Advanced => ["code", "code id_token"],
            _ when isFapi2 => ["code"],
            _ => ["code", "token", "id_token", "code token", "code id_token", "code id_token token", "id_token token"],
        };

        var grantTypes = new List<string> { "authorization_code" };
        if (responseTypes.Any(r => r.Contains("token")))   // token or id_token in the front channel
            grantTypes.Add("implicit");
        grantTypes.AddRange(["client_credentials", "refresh_token"]);
        if (opts.TokenExchangeEnabled)
            grantTypes.Add("urn:ietf:params:oauth:grant-type:token-exchange");
        if (opts.JwtBearerGrantEnabled)
            grantTypes.Add("urn:ietf:params:oauth:grant-type:jwt-bearer");
        if (opts.DeviceFlowEnabled)
            grantTypes.Add("urn:ietf:params:oauth:grant-type:device_code");
        if (opts.CibaEnabled)
            grantTypes.Add("urn:ietf:params:oauth:grant-type:ciba");
        if (opts.VciEnabled)
            grantTypes.Add(Vci.CredentialOfferService.PreAuthorizedCodeGrantType);

        // Client authentication: FAPI allows only private_key_jwt and mTLS (see ClientAuthenticator).
        var tokenAuthMethods = isFapi
            ? new List<string> { "private_key_jwt" }
            : ["client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"];
        if (opts.MtlsEnabled)
            tokenAuthMethods.AddRange(["tls_client_auth", "self_signed_tls_client_auth"]);
        if (!isFapi && opts.ClientAttestationTrustedAttesters.Count > 0)
            tokenAuthMethods.Add(Token.ClientAttestationValidator.AuthMethod);

        // Public clients authenticate with PKCE only; introspection and revocation still
        // require a credential, so "none" is advertised for the token endpoint only.
        var tokenEndpointAuthMethods = isFapi ? tokenAuthMethods : new List<string>(tokenAuthMethods) { "none" };
        List<string> assertionAlgs = isFapi
            ? [.. KeyRing.SupportedSigningAlgorithms]
            : [.. KeyRing.SupportedSigningAlgorithms, "HS256", "HS384", "HS512"];

        // Request objects can only be encrypted to the provider when it holds encryption keys.
        var requestEncryptionAlgs = opts.JarEnabled && _keys.EncryptionAlgorithms.Count > 0 ? _keys.EncryptionAlgorithms : null;

        var authorizationDetailsTypes = new List<string>();
        if (opts.RichAuthorizationRequestsEnabled)
            authorizationDetailsTypes.AddRange(opts.AuthorizationDetailsTypesSupported);
        if (opts.VciEnabled && !authorizationDetailsTypes.Contains(Vci.CredentialAuthorizationDetails.Type))
            authorizationDetailsTypes.Add(Vci.CredentialAuthorizationDetails.Type);

        IReadOnlyList<string> encryptionAlgs = [.. KeyRing.SupportedEncryptionAlgorithms];
        IReadOnlyList<string> contentEncryptionAlgs = [.. KeyRing.SupportedContentEncryptionAlgorithms];

        return new DiscoveryDocument
        {
            Issuer = issuer,
            AuthorizationEndpoint = Abs(opts.AuthorizationEndpoint),
            TokenEndpoint = Abs(opts.TokenEndpoint),
            UserInfoEndpoint = Abs(opts.UserInfoEndpoint),
            IntrospectionEndpoint = Abs(opts.IntrospectionEndpoint),
            RevocationEndpoint = Abs(opts.RevocationEndpoint),
            JwksUri = Abs(opts.JwksEndpoint),
            ResponseTypesSupported = responseTypes,
            GrantTypesSupported = grantTypes,
            SubjectTypesSupported = subjectTypes,
            IdTokenSigningAlgValuesSupported = _keys.SigningAlgorithms,
            TokenEndpointAuthMethodsSupported = tokenEndpointAuthMethods,
            TokenEndpointAuthSigningAlgValuesSupported = assertionAlgs,
            IntrospectionEndpointAuthMethodsSupported = tokenAuthMethods,
            RevocationEndpointAuthMethodsSupported = tokenAuthMethods,
            CodeChallengeMethodsSupported = opts.AllowPlainPkce ? ["S256", "plain"] : ["S256"],
            ScopesSupported = opts.Scopes.Select(s => s.Name).ToList(),
            ResponseModesSupported = responseModes,
            ClaimsParameterSupported = true,
            ClaimsSupported = ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid",
                .. Claims.ClaimsEngine.ClaimsForScopes(opts.Scopes.Select(s => s.Name), opts.Scopes).Order()],
            PromptValuesSupported = ["none", "login", "consent", "select_account"],
            RequestUriParameterSupported = false,
            AuthorizationResponseIssParameterSupported = opts.IssuerIdentificationEnabled,
            EndSessionEndpoint = opts.LogoutEnabled ? Abs(opts.EndSessionEndpoint) : null,
            RegistrationEndpoint = opts.DcrEnabled ? Abs(opts.RegistrationEndpoint) : null,
            BackChannelLogoutSupported = opts.BackChannelLogoutEnabled,
            BackChannelLogoutSessionSupported = opts.BackChannelLogoutEnabled,
            FrontChannelLogoutSupported = opts.LogoutEnabled && opts.FrontChannelLogoutEnabled,
            FrontChannelLogoutSessionSupported = opts.LogoutEnabled && opts.FrontChannelLogoutEnabled,

            // ── Phase 4 ──────────────────────────────────────────────────────
            PushedAuthorizationRequestEndpoint = opts.PushedAuthorizationEnabled
                ? Abs(opts.PushedAuthorizationEndpoint) : null,
            RequirePushedAuthorizationRequests = opts.RequirePushedAuthorization,
            RequestParameterSupported = opts.JarEnabled,
            RequestObjectSigningAlgValuesSupported = opts.JarEnabled ? [.. KeyRing.SupportedSigningAlgorithms] : null,
            RequestObjectEncryptionAlgValuesSupported = requestEncryptionAlgs,
            RequestObjectEncryptionEncValuesSupported = requestEncryptionAlgs is null ? null : [.. KeyRing.SupportedContentDecryptionAlgorithms],
            RequireSignedRequestObject = opts.JarEnabled && opts.JarRequireSignedRequestObject,
            AuthorizationSigningAlgValuesSupported = opts.JarmEnabled
                ? _keys.SigningAlgorithms
                : null,
            ResourceIndicatorsSupported = opts.ResourceIndicatorsEnabled,
            AuthorizationDetailsTypesSupported = authorizationDetailsTypes.Count > 0 ? authorizationDetailsTypes : null,
            // ID tokens and UserInfo responses are encrypted to the client's keys (TokenFactory).
            IdTokenEncryptionAlgValuesSupported = encryptionAlgs,
            IdTokenEncryptionEncValuesSupported = contentEncryptionAlgs,
            UserInfoSigningAlgValuesSupported = _keys.SigningAlgorithms,
            UserInfoEncryptionAlgValuesSupported = encryptionAlgs,
            UserInfoEncryptionEncValuesSupported = contentEncryptionAlgs,

            // ── Phase 5 ──────────────────────────────────────────────────────
            DPoPSigningAlgValuesSupported = opts.DPoPEnabled ? [.. KeyRing.SupportedSigningAlgorithms] : null,
            TlsClientCertificateBoundAccessTokens = opts.MtlsEnabled,

            // ── Phase 6 ──────────────────────────────────────────────────────
            DeviceAuthorizationEndpoint = opts.DeviceFlowEnabled
                ? Abs(opts.DeviceAuthorizationEndpoint) : null,
            BackchannelAuthenticationEndpoint = opts.CibaEnabled
                ? Abs(opts.BackchannelAuthenticationEndpoint) : null,
            BackchannelTokenDeliveryModesSupported = opts.CibaEnabled
                ? ["poll", "ping", "push"] : null,
            BackchannelAuthenticationRequestSigningAlgValuesSupported = opts.CibaEnabled
                ? [.. KeyRing.SupportedSigningAlgorithms]
                : null,
            BackchannelUserCodeParameterSupported = opts.CibaEnabled,

            // ── Phase 8 ──────────────────────────────────────────────────────
            ClientRegistrationTypesSupported = opts.FederationEnabled
                ? [.. FederationRegistrationTypes(opts)]
                : null,
            FederationRegistrationEndpoint = opts.FederationEnabled && opts.FederationExplicitRegistrationEnabled
                ? Abs(opts.FederationRegistrationEndpoint) : null,

            PreAuthorizedGrantAnonymousAccessSupported = opts.VciEnabled && opts.VciPreAuthorizedAnonymousAccess,
            ClientIdMetadataDocumentSupported = opts.ClientIdMetadataDocumentEnabled,
        };
    }

    private static IEnumerable<string> FederationRegistrationTypes(ProviderOptions opts)
    {
        if (opts.FederationAutomaticRegistrationEnabled) yield return "automatic";
        if (opts.FederationExplicitRegistrationEnabled) yield return "explicit";
    }

    /// <summary>Returns the JSON Web Key Set containing all active public keys.</summary>
    public object BuildJwks() => new
    {
        // Every published key: active, upcoming (pre-published for rotation) and retiring.
        keys = _keys.GetPublicJwks()
    };
}
