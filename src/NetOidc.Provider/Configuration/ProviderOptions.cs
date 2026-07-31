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

    // -- DCR (RFC 7591 / RFC 7592) --

    /// <summary>When true, <c>POST /connect/register</c> is active.</summary>
    public bool DcrEnabled { get; set; } = false;

    public string RegistrationEndpoint { get; set; } = "/connect/register";

    /// <summary>
    /// When set, every registration request must carry this value as a Bearer token.
    /// Set to <c>null</c> to allow open registration.
    /// </summary>
    public string? InitialAccessToken { get; set; }

    /// <summary>
    /// When true, the registration_access_token is rotated on every PUT (update) request.
    /// </summary>
    public bool DcrRotateRegistrationTokens { get; set; } = false;

    /// <summary>
    /// Lifetime in seconds of dynamically issued client_secrets; 0 = non-expiring.
    /// </summary>
    public int ClientSecretLifetimeSeconds { get; set; } = 0;

    /// <summary>
    /// Optional hook called after client metadata is built. Throw to reject registration.
    /// </summary>
    public Func<Abstractions.Models.Client, CancellationToken, Task>? ValidateDynamicClient { get; set; }

    // -- Logout / Session --

    /// <summary>
    /// When true, the end_session endpoint is active and OIDC sessions are tracked.
    /// </summary>
    public bool LogoutEnabled { get; set; } = false;

    /// <summary>
    /// When true (and <see cref="LogoutEnabled"/> is true), back-channel logout tokens
    /// are sent to clients that have a <c>backchannel_logout_uri</c> registered.
    /// </summary>
    public bool BackChannelLogoutEnabled { get; set; } = false;

    /// <summary>Lifetime in seconds of back-channel logout tokens (default 120 s).</summary>
    public int LogoutTokenLifetimeSeconds { get; set; } = 120;

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

    // -- Subject identifier types (OIDC Core §8) --

    /// <summary>"public" (default) or "pairwise" (OIDC Core §8.1).</summary>
    public string SubjectType { get; set; } = "public";

    /// <summary>
    /// Secret used to compute pairwise sub identifiers. Required when <see cref="SubjectType"/>
    /// is "pairwise". Defaults to a value derived from <see cref="Issuer"/> if unset.
    /// </summary>
    public string? PairwiseSalt { get; set; }

    // -- RFC 9207 Authorization Server Issuer Identification --

    /// <summary>
    /// When true, the <c>iss</c> parameter is added to every authorization response
    /// (RFC 9207). Enabled by default.
    /// </summary>
    public bool IssuerIdentificationEnabled { get; set; } = true;

    // -- RFC 8252 OAuth 2.0 for Native Apps --

    /// <summary>
    /// When true, loopback redirect URIs (localhost/127.0.0.1/::1) are matched by
    /// host+path only, ignoring the port (RFC 8252 §7.3). Enabled by default.
    /// </summary>
    public bool AllowNativeAppRedirects { get; set; } = true;

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
