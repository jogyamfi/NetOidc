using System.Text.Json.Nodes;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Conformance;

/// <summary>Host settings (section <c>Conformance</c>, overridable on the command line).</summary>
internal sealed class ConformanceSettings
{
    /// <summary>The OP's issuer; the suite container reaches the host as <c>host.docker.internal</c>.</summary>
    public string Issuer { get; set; } = "https://host.docker.internal:8990";

    /// <summary>The suite's public base URL; redirect URIs live under it.</summary>
    public string SuiteBaseUrl { get; set; } = "https://localhost.emobix.co.uk:8443";

    /// <summary>The <c>alias</c> in the plan configuration; part of every suite callback URL.</summary>
    public string Alias { get; set; } = "netoidc";

    /// <summary>Which OP configuration to run; see <see cref="ConformanceProfiles"/>.</summary>
    public string Profile { get; set; } = "oidcc";

    /// <summary>When set, the plan configurations for the profile are written here at startup.</summary>
    public string? SuiteConfigDir { get; set; }

    public string EndSessionPath { get; set; } = "/connect/end_session";

    /// <summary>A URL under the suite for this alias, e.g. <c>callback</c>.</summary>
    public string SuiteUrl(string path) => $"{SuiteBaseUrl.TrimEnd('/')}/test/a/{Alias}/{path}";

    public string Op(string path) => Issuer.TrimEnd('/') + path;
}

/// <summary>One OP configuration, and the plan configurations the suite runs against it.</summary>
internal sealed class ConformanceProfile
{
    public required string Name { get; init; }
    public string DefaultSigningAlgorithm { get; init; } = "RS256";
    public bool UsesMtls { get; init; }
    public required Action<ProviderOptions, ConformanceSettings, ClientCredentialStore> Configure { get; init; }

    /// <summary>File name → plan configuration JSON.</summary>
    public required Func<ConformanceSettings, ClientCredentialStore, IReadOnlyDictionary<string, JsonObject>> SuiteConfigs { get; init; }
}

internal static class ConformanceProfiles
{
    /// <summary>The secret of every confidential static client (long enough for HS512).</summary>
    public const string ClientSecret = "conformance-secret-0123456789-0123456789-0123456789-0123456789-0123456789";

    public static ConformanceProfile Parse(string name) => name switch
    {
        "oidcc" => Oidcc,
        "fapi2" => Fapi2(FapiProfile.Fapi2Security),
        "fapi2-ms" => Fapi2(FapiProfile.Fapi2MessageSigning),
        "fapi1" => Fapi1,
        "fapi-ciba" => FapiCiba,
        _ => throw new ArgumentException($"Unknown conformance profile '{name}'. Known: oidcc, fapi2, fapi2-ms, fapi1, fapi-ciba."),
    };

    // ── OpenID Connect ──────────────────────────────────────────────────────

    /// <summary>
    /// OpenID Connect OP: Basic, Implicit, Hybrid, Form Post, Config, Dynamic, RP-Initiated,
    /// Front- and Back-Channel Logout. One configuration serves all of those plans.
    /// </summary>
    private static readonly ConformanceProfile Oidcc = new()
    {
        Name = "oidcc",
        Configure = (o, s, _) =>
        {
            o.LogoutEnabled = true;
            o.FrontChannelLogoutEnabled = true;
            o.BackChannelLogoutEnabled = true;
            o.DcrEnabled = true;
            o.DcrAllowedGrantTypes = ["authorization_code", "implicit", "refresh_token"];
            // The Dynamic profile's relying party does not send PKCE.
            o.DcrRequirePkceByDefault = false;
            // The suite runs on this machine (localhost.emobix.co.uk resolves to 127.0.0.1).
            o.DcrAllowPrivateNetworkUris = true;
            // The Dynamic profile requires request_uri (OIDC Core §15.2) and RS256 request objects.
            o.JarEnabled = true;
            o.RequestUriParameterSupported = true;
            o.IssueRefreshTokens = true;
            o.StaticClients =
            [
                OidccClient(s, "netoidc-client1", "client_secret_basic"),
                OidccClient(s, "netoidc-client2", "client_secret_basic"),
                OidccClient(s, "netoidc-post1", "client_secret_post"),
                OidccClient(s, "netoidc-post2", "client_secret_post"),
                // One pair per logout plan, so each plan only receives the notifications it tests.
                OidccClient(s, "netoidc-rp1", "client_secret_basic", Logout.RpInitiated),
                OidccClient(s, "netoidc-rp2", "client_secret_basic", Logout.RpInitiated),
                OidccClient(s, "netoidc-fc1", "client_secret_basic", Logout.FrontChannel),
                OidccClient(s, "netoidc-fc2", "client_secret_basic", Logout.FrontChannel),
                OidccClient(s, "netoidc-bc1", "client_secret_basic", Logout.BackChannel),
                OidccClient(s, "netoidc-bc2", "client_secret_basic", Logout.BackChannel),
            ];
        },
        SuiteConfigs = (s, _) => new Dictionary<string, JsonObject>
        {
            ["oidcc-static.json"] = new()
            {
                ["alias"] = s.Alias,
                ["description"] = "NetOidc OP, static clients",
                ["server"] = Server(s),
                ["client"] = new JsonObject { ["client_id"] = "netoidc-client1", ["client_secret"] = ClientSecret },
                ["client2"] = new JsonObject { ["client_id"] = "netoidc-client2", ["client_secret"] = ClientSecret },
                ["client_secret_post"] = new JsonObject { ["client_id"] = "netoidc-post1", ["client_secret"] = ClientSecret },
                ["browser"] = SuiteBrowser.Default(s),
                ["override"] = SuiteBrowser.OidccOverrides(s),
            },
            ["oidcc-logout-rp.json"] = LogoutConfig(s, "netoidc-rp"),
            ["oidcc-logout-frontchannel.json"] = LogoutConfig(s, "netoidc-fc"),
            ["oidcc-logout-backchannel.json"] = LogoutConfig(s, "netoidc-bc"),
            ["oidcc-dynamic.json"] = new()
            {
                ["alias"] = s.Alias,
                ["description"] = "NetOidc OP, dynamic client registration",
                ["server"] = Server(s),
                ["client"] = new JsonObject { ["client_name"] = "netoidc-dynamic-1" },
                ["client2"] = new JsonObject { ["client_name"] = "netoidc-dynamic-2" },
                ["browser"] = SuiteBrowser.Default(s),
                ["override"] = SuiteBrowser.OidccOverrides(s),
            },
        },
    };

    private enum Logout { None, RpInitiated, FrontChannel, BackChannel }

    private static JsonObject LogoutConfig(ConformanceSettings s, string prefix) => new()
    {
        ["alias"] = s.Alias,
        ["description"] = $"NetOidc OP, logout clients {prefix}",
        ["server"] = Server(s),
        ["client"] = new JsonObject { ["client_id"] = prefix + "1", ["client_secret"] = ClientSecret },
        ["client2"] = new JsonObject { ["client_id"] = prefix + "2", ["client_secret"] = ClientSecret },
        ["browser"] = SuiteBrowser.Default(s),
        ["override"] = SuiteBrowser.OidccOverrides(s),
    };

    private static Client OidccClient(ConformanceSettings s, string clientId, string authMethod, Logout logout = Logout.None) => new()
    {
        ClientId = clientId,
        ClientSecret = ClientSecret,
        TokenEndpointAuthMethod = authMethod,
        AllowedGrantTypes = ["authorization_code", "implicit", "refresh_token"],
        ResponseTypes = ["code", "id_token", "id_token token", "code id_token", "code token", "code id_token token"],
        AllowedScopes = [.. ConformanceUser.Scopes.Select(sc => sc.Name)],
        RedirectUris = [s.SuiteUrl("callback"), s.SuiteUrl("callback?dummy1=lorem&dummy2=ipsum")],
        PostLogoutRedirectUris = logout == Logout.None ? [] : [s.SuiteUrl("post_logout_redirect")],
        FrontChannelLogoutUri = logout == Logout.FrontChannel ? s.SuiteUrl("frontchannel_logout") : null,
        FrontChannelLogoutSessionRequired = logout == Logout.FrontChannel,
        BackChannelLogoutUri = logout == Logout.BackChannel ? s.SuiteUrl("backchannel_logout") : null,
        BackChannelLogoutSessionRequired = logout == Logout.BackChannel,
        RequirePkce = false,
        RequireConsent = false,
    };

    // ── FAPI ────────────────────────────────────────────────────────────────

    /// <summary>
    /// FAPI 2.0 Security Profile or Message Signing: PAR, PKCE, PS256, sender-constrained tokens
    /// (DPoP or mTLS). Clients: <c>fapi-pkjwt-1/2</c> (private_key_jwt) and <c>fapi-mtls-1/2</c>
    /// (self_signed_tls_client_auth).
    /// </summary>
    private static ConformanceProfile Fapi2(FapiProfile fapi) => new()
    {
        Name = fapi == FapiProfile.Fapi2MessageSigning ? "fapi2-ms" : "fapi2",
        DefaultSigningAlgorithm = "PS256",
        UsesMtls = true,
        Configure = (o, s, keys) =>
        {
            o.FapiProfile = fapi;
            o.FapiProfileValidationEnabled = true;
            o.PushedAuthorizationEnabled = true;
            o.RequirePushedAuthorization = true;
            o.DPoPEnabled = true;
            o.MtlsEnabled = true;
            o.IssueRefreshTokens = true;
            // FAPI 2.0 §5.3.2.1: refresh tokens are sender-constrained, so no rotation.
            o.RotateRefreshTokens = false;
            if (fapi == FapiProfile.Fapi2MessageSigning)
            {
                o.JarEnabled = true;
                o.JarRequireSignedRequestObject = true;
                o.JarmEnabled = true;
            }
            o.StaticClients = [.. FapiClients(s, keys, fapi1: false)];
        },
        SuiteConfigs = (s, keys) => new Dictionary<string, JsonObject>
        {
            [$"{(fapi == FapiProfile.Fapi2MessageSigning ? "fapi2-ms" : "fapi2")}-pkjwt.json"] = FapiConfig(s, keys, "fapi-pkjwt"),
            [$"{(fapi == FapiProfile.Fapi2MessageSigning ? "fapi2-ms" : "fapi2")}-mtls.json"] = FapiConfig(s, keys, "fapi-mtls"),
        },
    };

    /// <summary>FAPI 1.0 Advanced: request objects (or PAR), mTLS-bound tokens, PS256, hybrid or JARM.</summary>
    private static readonly ConformanceProfile Fapi1 = new()
    {
        Name = "fapi1",
        DefaultSigningAlgorithm = "PS256",
        UsesMtls = true,
        Configure = (o, s, keys) =>
        {
            o.FapiProfile = FapiProfile.Fapi1Advanced;
            o.FapiProfileValidationEnabled = true;
            o.PushedAuthorizationEnabled = true;
            o.JarEnabled = true;
            o.JarmEnabled = true;
            o.MtlsEnabled = true;
            o.IssueRefreshTokens = true;
            o.RotateRefreshTokens = false;
            o.StaticClients = [.. FapiClients(s, keys, fapi1: true)];
        },
        SuiteConfigs = (s, keys) => new Dictionary<string, JsonObject>
        {
            ["fapi1-pkjwt.json"] = FapiConfig(s, keys, "fapi-pkjwt"),
            ["fapi1-mtls.json"] = FapiConfig(s, keys, "fapi-mtls"),
        },
    };

    /// <summary>
    /// FAPI-CIBA: signed backchannel authentication requests, mTLS-bound tokens, poll and ping
    /// delivery. The host approves every request for the conformance user after a short delay,
    /// standing in for the End-User's authentication device.
    /// </summary>
    private static readonly ConformanceProfile FapiCiba = new()
    {
        Name = "fapi-ciba",
        DefaultSigningAlgorithm = "PS256",
        UsesMtls = true,
        Configure = (o, s, keys) =>
        {
            o.FapiProfile = FapiProfile.FapiCiba;
            o.FapiProfileValidationEnabled = true;
            o.CibaEnabled = true;
            o.CibaPollingIntervalSeconds = 2;
            o.MtlsEnabled = true;
            o.IssueRefreshTokens = true;
            o.RotateRefreshTokens = false;
            o.ProcessBackchannelAuthenticationRequest = (request, _) =>
            {
                CibaDevice.ApproveLater(request.AuthReqId);
                return Task.CompletedTask;
            };
            o.StaticClients =
            [
                .. new[] { "poll", "ping" }.SelectMany(mode => new[] { 1, 2 }.Select(n => new Client
                {
                    ClientId = $"fapi-ciba-{mode}-{n}",
                    TokenEndpointAuthMethod = "private_key_jwt",
                    JwksJson = keys[$"fapi-ciba-{mode}-{n}"].PublicJwksJson,
                    AllowedGrantTypes = ["urn:openid:params:grant-type:ciba", "refresh_token"],
                    AllowedScopes = [.. ConformanceUser.Scopes.Select(sc => sc.Name)],
                    CibaDeliveryMode = mode,
                    CibaClientNotificationEndpoint = mode == "ping" ? s.SuiteUrl("ciba-notification-endpoint") : null,
                    UseMtlsBoundTokens = true,
                    RequestObjectSigningAlg = "PS256",
                    IdTokenSignedResponseAlg = "PS256",
                })),
            ];
        },
        SuiteConfigs = (s, keys) => new Dictionary<string, JsonObject>
        {
            ["fapi-ciba-poll.json"] = CibaConfig(s, keys, "fapi-ciba-poll"),
            ["fapi-ciba-ping.json"] = CibaConfig(s, keys, "fapi-ciba-ping"),
        },
    };

    private static JsonObject CibaConfig(ConformanceSettings s, ClientCredentialStore keys, string prefix)
    {
        var config = FapiConfig(s, keys, prefix);
        foreach (var client in new[] { "client", "client2" })
        {
            config[client]!["hint_type"] = "login_hint";
            config[client]!["hint_value"] = ConformanceUser.Subject;
            config[client]!.AsObject().Remove("dpop_signing_alg");
        }
        config.Remove("browser");
        return config;
    }

    private static IEnumerable<Client> FapiClients(ConformanceSettings s, ClientCredentialStore keys, bool fapi1)
    {
        foreach (var (prefix, method) in new[] { ("fapi-pkjwt", "private_key_jwt"), ("fapi-mtls", "self_signed_tls_client_auth") })
        {
            foreach (var n in new[] { 1, 2 })
            {
                var id = $"{prefix}-{n}";
                yield return new Client
                {
                    ClientId = id,
                    TokenEndpointAuthMethod = method,
                    JwksJson = keys[id].PublicJwksJson,
                    AllowedGrantTypes = fapi1 ? ["authorization_code", "implicit", "refresh_token"] : ["authorization_code", "refresh_token"],
                    ResponseTypes = fapi1 ? ["code id_token", "code"] : ["code"],
                    AllowedScopes = [.. ConformanceUser.Scopes.Select(sc => sc.Name)],
                    RedirectUris = [s.SuiteUrl("callback"), s.SuiteUrl("callback?dummy1=lorem&dummy2=ipsum")],
                    // FAPI 1.0 Advanced requires PKCE only with PAR (enforced at the PAR endpoint).
                    RequirePkce = !fapi1,
                    RequireConsent = false,
                    UseMtlsBoundTokens = true,
                    IdTokenSignedResponseAlg = "PS256",
                    RequestObjectSigningAlg = "PS256",
                    AuthorizationSignedResponseAlg = "PS256",
                };
            }
        }
    }

    private static JsonObject FapiConfig(ConformanceSettings s, ClientCredentialStore keys, string prefix)
    {
        JsonObject Client(int n) => new()
        {
            ["client_id"] = $"{prefix}-{n}",
            ["scope"] = "openid profile",
            ["jwks"] = keys[$"{prefix}-{n}"].PrivateJwks(),
            ["dpop_signing_alg"] = "PS256",
        };
        return new JsonObject
        {
            ["alias"] = s.Alias,
            ["description"] = $"NetOidc OP, {s.Profile}, {prefix}",
            ["server"] = Server(s),
            ["client"] = Client(1),
            ["client2"] = Client(2),
            ["mtls"] = keys[$"{prefix}-1"].Mtls(),
            ["mtls2"] = keys[$"{prefix}-2"].Mtls(),
            ["resource"] = new JsonObject { ["resourceUrl"] = s.Op("/connect/userinfo") },
            ["browser"] = SuiteBrowser.Default(s),
            ["override"] = SuiteBrowser.FapiOverrides(s),
        };
    }

    private static JsonObject Server(ConformanceSettings s) => new()
    {
        ["discoveryUrl"] = s.Op("/.well-known/openid-configuration"),
    };
}
