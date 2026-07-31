using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Configuration;

/// <summary>All top-level configuration knobs for the provider.</summary>
public sealed class ProviderOptions
{
    /// <summary>Authorization server issuer URI (e.g. https://auth.example.com).</summary>
    public string Issuer { get; set; } = string.Empty;

    // -- Endpoint paths --

    public string DiscoveryEndpoint { get; set; } = "/.well-known/openid-configuration";
    public string JwksEndpoint { get; set; } = "/.well-known/jwks.json";
    public string AuthorizationEndpoint { get; set; } = "/connect/authorize";
    public string TokenEndpoint { get; set; } = "/connect/token";
    public string UserInfoEndpoint { get; set; } = "/connect/userinfo";
    public string IntrospectionEndpoint { get; set; } = "/connect/introspect";
    public string RevocationEndpoint { get; set; } = "/connect/revoke";
    public string EndSessionEndpoint { get; set; } = "/connect/end_session";

    // -- Interaction --

    /// <summary>Path the provider redirects to when the user is not authenticated.</summary>
    public string LoginPath { get; set; } = "/account/login";

    // -- Static configuration --

    public IList<Client> StaticClients { get; set; } = [];

    public IList<Scope> Scopes { get; set; } = [new Scope { Name = "openid" }];

    // -- Token lifetimes (seconds) --

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeSeconds { get; set; } = 86400;
    public int IdTokenLifetimeSeconds { get; set; } = 3600;
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 60;

    /// <summary>Issue refresh tokens alongside access tokens for authorization_code grants.</summary>
    public bool IssueRefreshTokens { get; set; } = true;

    // -- Claim sourcing --

    /// <summary>
    /// Called by the UserInfo endpoint to load profile claims for a subject.
    /// The second argument is the list of granted scopes. Default returns only sub.
    /// </summary>
    public Func<string, IReadOnlyList<string>, CancellationToken, Task<IReadOnlyDictionary<string, object>>>
        FindUserClaims { get; set; } =
            static (sub, _, _) => Task.FromResult<IReadOnlyDictionary<string, object>>(
                new Dictionary<string, object> { ["sub"] = sub });
}
