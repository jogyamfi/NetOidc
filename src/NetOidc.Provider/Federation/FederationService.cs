using System.Collections.Generic;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Federation;

/// <summary>
/// Builds and signs the provider's OpenID Federation 1.1 entity configuration
/// (OpenID Federation 1.1 §6).
/// The entity configuration is a self-signed entity statement containing the provider's
/// OIDC metadata, JWKS, and optional authority hints.
/// </summary>
public sealed class FederationService
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly SigningKeyProvider _keyProvider;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    public FederationService(IOptions<ProviderOptions> options, SigningKeyProvider keyProvider)
    {
        _options = options;
        _keyProvider = keyProvider;
    }

    /// <summary>
    /// Returns a signed entity-statement+jwt string containing this provider's entity configuration.
    /// </summary>
    public string BuildEntityConfiguration()
    {
        var opts = _options.Value;
        var issuer = opts.Issuer.TrimEnd('/');
        var now = DateTimeOffset.UtcNow;

        // Build the openid_provider metadata sub-object
        var opMetadata = BuildOpenIdProviderMetadata(opts, issuer);

        // Federation entity metadata (optional — organizational info)
        var federationEntityMetadata = new Dictionary<string, object>
        {
            ["federation_fetch_endpoint"] = issuer + "/.well-known/openid-federation",
        };

        var metadata = new Dictionary<string, object>
        {
            ["openid_provider"] = opMetadata,
            ["federation_entity"] = federationEntityMetadata,
        };

        var claims = new Dictionary<string, object>
        {
            ["iss"] = issuer,
            ["sub"] = issuer,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddSeconds(opts.FederationEntityStatementLifetimeSeconds).ToUnixTimeSeconds(),
            ["metadata"] = metadata,
            ["jwks"] = new Dictionary<string, object>
            {
                ["keys"] = new[] { _keyProvider.GetPublicJwk() }
            },
        };

        if (opts.FederationAuthorityHints.Count > 0)
            claims["authority_hints"] = opts.FederationAuthorityHints.ToArray();

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            IssuedAt = now.UtcDateTime,
            Expires = now.AddSeconds(opts.FederationEntityStatementLifetimeSeconds).UtcDateTime,
            SigningCredentials = _keyProvider.GetSigningCredentials(),
            TokenType = "entity-statement+jwt",
            Claims = claims,
        };

        return _jwtHandler.CreateToken(descriptor);
    }

    private static Dictionary<string, object> BuildOpenIdProviderMetadata(ProviderOptions opts, string issuer)
    {
        string Abs(string p) => issuer + p;

        var meta = new Dictionary<string, object>
        {
            ["issuer"] = issuer,
            ["authorization_endpoint"] = Abs(opts.AuthorizationEndpoint),
            ["token_endpoint"] = Abs(opts.TokenEndpoint),
            ["userinfo_endpoint"] = Abs(opts.UserInfoEndpoint),
            ["jwks_uri"] = Abs(opts.JwksEndpoint),
            ["response_types_supported"] = new[] { "code", "token", "id_token" },
            ["grant_types_supported"] = BuildGrantTypes(opts),
            ["subject_types_supported"] = opts.SubjectType == "pairwise"
                ? new[] { "pairwise", "public" }
                : new[] { "public" },
            ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
            ["token_endpoint_auth_methods_supported"] = new[]
            {
                "client_secret_basic", "client_secret_post", "private_key_jwt"
            },
            ["code_challenge_methods_supported"] = new[] { "S256", "plain" },
            ["scopes_supported"] = opts.Scopes.Select(s => s.Name).ToArray(),
        };

        if (opts.PushedAuthorizationEnabled)
        {
            meta["pushed_authorization_request_endpoint"] = Abs(opts.PushedAuthorizationEndpoint);
            meta["require_pushed_authorization_requests"] = opts.RequirePushedAuthorization;
        }

        if (opts.JarEnabled)
            meta["request_parameter_supported"] = true;

        if (opts.DcrEnabled)
            meta["registration_endpoint"] = Abs(opts.RegistrationEndpoint);

        // Federation registration types
        meta["client_registration_types_supported"] = opts.DcrEnabled
            ? new[] { "automatic", "explicit" }
            : new[] { "explicit" };

        return meta;
    }

    private static string[] BuildGrantTypes(ProviderOptions opts)
    {
        var types = new List<string> { "authorization_code", "client_credentials", "refresh_token" };
        if (opts.DeviceFlowEnabled)
            types.Add("urn:ietf:params:oauth:grant-type:device_code");
        if (opts.CibaEnabled)
            types.Add("urn:ietf:params:oauth:grant-type:ciba");
        return types.ToArray();
    }
}
