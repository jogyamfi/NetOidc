using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Authorization;

namespace NetOidc.Provider.Configuration;

/// <summary>
/// Validates <see cref="ProviderOptions"/> at startup so that an unsafe or unusable
/// configuration fails fast instead of running.
/// </summary>
internal sealed class ProviderOptionsValidator : IValidateOptions<ProviderOptions>
{
    /// <summary>Minimum pairwise salt length in bytes (256 bits).</summary>
    public const int MinPairwiseSaltBytes = 32;

    private static readonly HashSet<string> KnownAuthMethods =
    [
        "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt",
        "tls_client_auth", "self_signed_tls_client_auth", "none", "attest_jwt_client_auth",
    ];

    private readonly IHostEnvironment? _environment;

    public ProviderOptionsValidator(IHostEnvironment? environment = null) => _environment = environment;

    public ValidateOptionsResult Validate(string? name, ProviderOptions opts)
    {
        var errors = new List<string>();

        ValidateIssuer(opts, errors);
        ValidateLifetimes(opts, errors);
        ValidatePaths(opts, errors);
        ValidateFeatures(opts, errors);
        ValidatePairwise(opts, errors);
        ValidateClients(opts, errors);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    private void ValidateIssuer(ProviderOptions opts, List<string> errors)
    {
        // OIDC Discovery §3 / RFC 8414 §2: an https URL with no query or fragment.
        if (!Uri.TryCreate(opts.Issuer, UriKind.Absolute, out var issuer))
        {
            errors.Add("Issuer must be an absolute URL (e.g. https://auth.example.com).");
            return;
        }
        if (!string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment))
            errors.Add("Issuer must not contain a query or fragment.");
        if (issuer.Scheme != Uri.UriSchemeHttps && !(_environment?.IsDevelopment() ?? false))
            errors.Add("Issuer must use https (http is allowed in the Development environment only).");
    }

    private static void ValidateLifetimes(ProviderOptions opts, List<string> errors)
    {
        void Positive(string name, int value)
        {
            if (value <= 0) errors.Add($"{name} must be greater than zero.");
        }
        void NonNegative(string name, int value)
        {
            if (value < 0) errors.Add($"{name} must not be negative.");
        }

        Positive(nameof(opts.AccessTokenLifetimeSeconds), opts.AccessTokenLifetimeSeconds);
        Positive(nameof(opts.RefreshTokenLifetimeSeconds), opts.RefreshTokenLifetimeSeconds);
        Positive(nameof(opts.IdTokenLifetimeSeconds), opts.IdTokenLifetimeSeconds);
        Positive(nameof(opts.AuthorizationCodeLifetimeSeconds), opts.AuthorizationCodeLifetimeSeconds);
        Positive(nameof(opts.PushedAuthorizationLifetimeSeconds), opts.PushedAuthorizationLifetimeSeconds);
        Positive(nameof(opts.DeviceCodeLifetimeSeconds), opts.DeviceCodeLifetimeSeconds);
        Positive(nameof(opts.CibaAuthReqIdLifetimeSeconds), opts.CibaAuthReqIdLifetimeSeconds);
        Positive(nameof(opts.CibaMaxRequestedExpirySeconds), opts.CibaMaxRequestedExpirySeconds);
        Positive(nameof(opts.VciNonceLifetimeSeconds), opts.VciNonceLifetimeSeconds);
        Positive(nameof(opts.InteractionLifetimeSeconds), opts.InteractionLifetimeSeconds);
        Positive(nameof(opts.SessionLifetimeSeconds), opts.SessionLifetimeSeconds);
        Positive(nameof(opts.LogoutTokenLifetimeSeconds), opts.LogoutTokenLifetimeSeconds);
        Positive(nameof(opts.DPoPProofLifetimeSeconds), opts.DPoPProofLifetimeSeconds);
        Positive(nameof(opts.DPoPNonceLifetimeSeconds), opts.DPoPNonceLifetimeSeconds);
        Positive(nameof(opts.ClientAssertionMaxLifetimeSeconds), opts.ClientAssertionMaxLifetimeSeconds);
        Positive(nameof(opts.DeviceUserCodeMaxFailedAttempts), opts.DeviceUserCodeMaxFailedAttempts);
        Positive(nameof(opts.DeviceUserCodeFailureWindowSeconds), opts.DeviceUserCodeFailureWindowSeconds);
        Positive(nameof(opts.VciPreAuthorizedCodeLifetimeSeconds), opts.VciPreAuthorizedCodeLifetimeSeconds);
        Positive(nameof(opts.VciTxCodeMaxAttempts), opts.VciTxCodeMaxAttempts);
        Positive(nameof(opts.VciBatchSize), opts.VciBatchSize);
        Positive(nameof(opts.VciDeferredTransactionLifetimeSeconds), opts.VciDeferredTransactionLifetimeSeconds);
        Positive(nameof(opts.VciNotificationLifetimeSeconds), opts.VciNotificationLifetimeSeconds);
        Positive(nameof(opts.FederationEntityStatementLifetimeSeconds), opts.FederationEntityStatementLifetimeSeconds);
        Positive(nameof(opts.FederationMaxChainLength), opts.FederationMaxChainLength);
        Positive(nameof(opts.FederationMaxStatementBytes), opts.FederationMaxStatementBytes);
        Positive(nameof(opts.ClientIdMetadataDocumentMaxBytes), opts.ClientIdMetadataDocumentMaxBytes);
        NonNegative(nameof(opts.ClientIdMetadataDocumentCacheSeconds), opts.ClientIdMetadataDocumentCacheSeconds);
        NonNegative(nameof(opts.DevicePollingIntervalSeconds), opts.DevicePollingIntervalSeconds);
        NonNegative(nameof(opts.CibaPollingIntervalSeconds), opts.CibaPollingIntervalSeconds);
        NonNegative(nameof(opts.UnauthenticatedRequestsPerMinute), opts.UnauthenticatedRequestsPerMinute);
    }

    private static void ValidatePaths(ProviderOptions opts, List<string> errors)
    {
        (string Name, string Value)[] paths =
        [
            (nameof(opts.DiscoveryEndpoint), opts.DiscoveryEndpoint),
            (nameof(opts.JwksEndpoint), opts.JwksEndpoint),
            (nameof(opts.AuthorizationEndpoint), opts.AuthorizationEndpoint),
            (nameof(opts.TokenEndpoint), opts.TokenEndpoint),
            (nameof(opts.UserInfoEndpoint), opts.UserInfoEndpoint),
            (nameof(opts.IntrospectionEndpoint), opts.IntrospectionEndpoint),
            (nameof(opts.RevocationEndpoint), opts.RevocationEndpoint),
            (nameof(opts.EndSessionEndpoint), opts.EndSessionEndpoint),
            (nameof(opts.RegistrationEndpoint), opts.RegistrationEndpoint),
            (nameof(opts.PushedAuthorizationEndpoint), opts.PushedAuthorizationEndpoint),
            (nameof(opts.DeviceAuthorizationEndpoint), opts.DeviceAuthorizationEndpoint),
            (nameof(opts.DeviceVerificationUri), opts.DeviceVerificationUri),
            (nameof(opts.BackchannelAuthenticationEndpoint), opts.BackchannelAuthenticationEndpoint),
            (nameof(opts.VciCredentialEndpoint), opts.VciCredentialEndpoint),
            (nameof(opts.VciNonceEndpoint), opts.VciNonceEndpoint),
            (nameof(opts.VciCredentialOfferEndpoint), opts.VciCredentialOfferEndpoint),
            (nameof(opts.VciDeferredCredentialEndpoint), opts.VciDeferredCredentialEndpoint),
            (nameof(opts.VciNotificationEndpoint), opts.VciNotificationEndpoint),
            (nameof(opts.FederationRegistrationEndpoint), opts.FederationRegistrationEndpoint),
            (nameof(opts.LoginPath), opts.LoginPath),
            (nameof(opts.ConsentPath), opts.ConsentPath),
            (nameof(opts.LogoutConfirmationPath), opts.LogoutConfirmationPath),
        ];
        foreach (var (pathName, value) in paths)
            if (string.IsNullOrEmpty(value) || !value.StartsWith('/') || value.StartsWith("//"))
                errors.Add($"{pathName} must be an absolute path starting with '/'.");
    }

    private static void ValidateFeatures(ProviderOptions opts, List<string> errors)
    {
        if (!Jose.KeyRing.SupportedSigningAlgorithms.Contains(opts.DefaultSigningAlgorithm))
            errors.Add($"DefaultSigningAlgorithm '{opts.DefaultSigningAlgorithm}' is not supported.");

        if (opts.VciEnabled && opts.IssueCredential is null)
            errors.Add("VciEnabled requires IssueCredential.");

        if (opts.CibaEnabled && opts.ProcessBackchannelAuthenticationRequest is null)
            errors.Add("CibaEnabled requires ProcessBackchannelAuthenticationRequest to start out-of-band authentication.");

        if (opts.FederationEnabled)
        {
            foreach (var (anchor, jwks) in opts.FederationTrustAnchors)
            {
                if (!Uri.TryCreate(anchor, UriKind.Absolute, out var anchorUri) || anchorUri.Scheme != Uri.UriSchemeHttps)
                    errors.Add($"FederationTrustAnchors entry '{anchor}' must be an https entity identifier.");
                if (Federation.EntityStatement.TryJwks(jwks) is not { Keys.Count: > 0 })
                    errors.Add($"FederationTrustAnchors entry '{anchor}' must map to a JWKS with at least one key.");
            }
            // Automatically registered RPs authenticate every authorization request with a
            // request object, so they cannot work without JAR.
            if (opts.FederationAutomaticRegistrationEnabled && opts.FederationTrustAnchors.Count > 0 && !opts.JarEnabled)
                errors.Add("FederationAutomaticRegistrationEnabled requires JarEnabled.");
        }

        if (opts.RequestUriParameterSupported && !opts.JarEnabled)
            errors.Add("RequestUriParameterSupported requires JarEnabled.");

        foreach (var (attester, jwks) in opts.ClientAttestationTrustedAttesters)
            if (Federation.EntityStatement.TryJwks(jwks) is not { Keys.Count: > 0 })
                errors.Add($"ClientAttestationTrustedAttesters entry '{attester}' must map to a JWKS with at least one key.");
        if (opts.StaticClients.Any(c => c.TokenEndpointAuthMethod == "attest_jwt_client_auth") &&
            opts.ClientAttestationTrustedAttesters.Count == 0)
            errors.Add("attest_jwt_client_auth clients require ClientAttestationTrustedAttesters.");

        if (opts.RequirePushedAuthorization && !opts.PushedAuthorizationEnabled)
            errors.Add("RequirePushedAuthorization requires PushedAuthorizationEnabled.");

        if (opts.ResourceIndicatorsEnabled)
        {
            if (opts.AllowedResources.Count == 0)
                errors.Add("ResourceIndicatorsEnabled requires AllowedResources.");
            foreach (var resource in opts.AllowedResources)
                if (!Uri.TryCreate(resource, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
                    errors.Add($"AllowedResources entry '{resource}' must be an absolute URI without a fragment.");
        }

        if (opts.MtlsClientCertificateHeader is not null && opts.MtlsTrustedProxies.Count == 0)
            errors.Add("MtlsClientCertificateHeader requires MtlsTrustedProxies (otherwise the header is never honoured).");

        foreach (var origin in opts.CorsAllowedOrigins)
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") ||
                uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query))
                errors.Add($"CorsAllowedOrigins entry '{origin}' must be an origin such as https://app.example.com.");
    }

    private static void ValidatePairwise(ProviderOptions opts, List<string> errors)
    {
        if (!string.Equals(opts.SubjectType, "pairwise", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.Equals(opts.SubjectType, "public", StringComparison.OrdinalIgnoreCase))
                errors.Add("SubjectType must be \"public\" or \"pairwise\".");
            return;
        }

        // OIDC Core §8.1: pairwise identifiers must not be computable by third parties, so the
        // salt must be a secret — never derived from public values such as the issuer.
        if (string.IsNullOrEmpty(opts.PairwiseSalt) ||
            Encoding.UTF8.GetByteCount(opts.PairwiseSalt) < MinPairwiseSaltBytes)
            errors.Add($"PairwiseSalt must be a secret of at least {MinPairwiseSaltBytes} bytes " +
                       "when SubjectType is \"pairwise\".");

        foreach (var client in opts.StaticClients)
        {
            var hosts = client.RedirectUris
                .Select(u => Uri.TryCreate(u, UriKind.Absolute, out var parsed) ? parsed.Host : u)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            if (hosts > 1 && client.SectorIdentifierUri is null)
                errors.Add($"client '{client.ClientId}' has redirect URIs on {hosts} hosts; " +
                           "SectorIdentifierUri is required for pairwise subjects (OIDC Core §8.1).");
        }
    }

    private static void ValidateClients(ProviderOptions opts, List<string> errors)
    {
        foreach (var group in opts.StaticClients.GroupBy(c => c.ClientId).Where(g => g.Count() > 1))
            errors.Add($"client_id '{group.Key}' is configured more than once.");

        foreach (var client in opts.StaticClients)
        {
            var id = client.ClientId;
            var method = client.TokenEndpointAuthMethod;
            if (!KnownAuthMethods.Contains(method))
                errors.Add($"client '{id}': unknown TokenEndpointAuthMethod '{method}'.");
            if (method is "client_secret_basic" or "client_secret_post" or "client_secret_jwt" &&
                string.IsNullOrEmpty(client.ClientSecret))
                errors.Add($"client '{id}': {method} requires a ClientSecret.");
            if (method is "private_key_jwt" or "self_signed_tls_client_auth" && string.IsNullOrEmpty(client.JwksJson))
                errors.Add($"client '{id}': {method} requires JwksJson.");
            if (method == "tls_client_auth" &&
                client.TlsClientAuthSubjectDn is null && client.TlsClientAuthSanDns is null &&
                client.TlsClientAuthSanUri is null && client.TlsClientAuthSanIp is null)
                errors.Add($"client '{id}': tls_client_auth requires a subject DN or SAN to match.");
            if (method == "none" && client.ClientSecret is not null)
                errors.Add($"client '{id}': a public client (none) must not have a ClientSecret.");

            foreach (var responseType in client.ResponseTypes)
            {
                var normalized = AuthorizationEndpointHandler.NormalizeResponseType(responseType);
                if (normalized.Split(' ').Any(t => t is not ("code" or "token" or "id_token")))
                    errors.Add($"client '{id}': unknown response type '{responseType}'.");
            }

            foreach (var alg in new[] { client.IdTokenSignedResponseAlg, client.AuthorizationSignedResponseAlg, client.UserInfoSignedResponseAlg })
                if (alg is not null && !Jose.KeyRing.SupportedSigningAlgorithms.Contains(alg))
                    errors.Add($"client '{id}': signing algorithm '{alg}' is not supported.");

            foreach (var (alg, enc) in new[]
            {
                (client.IdTokenEncryptedResponseAlg, client.IdTokenEncryptedResponseEnc),
                (client.UserInfoEncryptedResponseAlg, client.UserInfoEncryptedResponseEnc),
            })
            {
                if (alg is not null && !Jose.KeyRing.SupportedEncryptionAlgorithms.Contains(alg))
                    errors.Add($"client '{id}': encryption algorithm '{alg}' is not supported.");
                if (enc is not null && !Jose.KeyRing.SupportedContentEncryptionAlgorithms.Contains(enc))
                    errors.Add($"client '{id}': content encryption '{enc}' is not supported.");
                if (enc is not null && alg is null)
                    errors.Add($"client '{id}': an encrypted response enc requires the matching alg.");
                if (alg is not null && string.IsNullOrEmpty(client.JwksJson))
                    errors.Add($"client '{id}': encrypted responses require JwksJson with an encryption key.");
            }
        }
    }
}
