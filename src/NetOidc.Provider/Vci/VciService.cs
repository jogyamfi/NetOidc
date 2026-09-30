using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Vci;

/// <summary>
/// Manages c_nonce values for the credential endpoint (OID4VCI 1.0 §8.2).
/// Nonces are single-use and expire after <see cref="ProviderOptions.VciNonceLifetimeSeconds"/>.
/// They are stored through <see cref="IAdapter{T}"/> so multiple instances can share them.
/// </summary>
internal sealed class VciService
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IAdapter<CredentialNonce> _nonces;

    public VciService(IOptions<ProviderOptions> options, IAdapter<CredentialNonce> nonces)
    {
        _options = options;
        _nonces = nonces;
    }

    /// <summary>Issues a new c_nonce and stores it for later validation.</summary>
    public async Task<string> IssueNonceAsync(CancellationToken ct = default)
    {
        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var lifetime = TimeSpan.FromSeconds(NonceLifetimeSeconds);
        await _nonces.StoreAsync(nonce,
            new CredentialNonce { Nonce = nonce, ExpiresAt = DateTimeOffset.UtcNow + lifetime }, lifetime, ct);
        return nonce;
    }

    /// <summary>
    /// Validates and consumes a c_nonce (single-use).
    /// Returns true when the nonce is known and not expired.
    /// </summary>
    public async Task<bool> ConsumeNonceAsync(string nonce, CancellationToken ct = default) =>
        await _nonces.ConsumeAsync(nonce, ct) is { } entry && entry.ExpiresAt > DateTimeOffset.UtcNow;

    public int NonceLifetimeSeconds => _options.Value.VciNonceLifetimeSeconds;

    /// <summary>
    /// The credential issuer metadata (OID4VCI 1.0 §12.2.4), advertising only the endpoints and
    /// features that are configured; <c>null</c> when VCI is disabled.
    /// </summary>
    public Dictionary<string, object>? BuildIssuerMetadata()
    {
        var opts = _options.Value;
        if (!opts.VciEnabled)
            return null;

        var issuer = CredentialIssuer(opts);
        string Abs(string path) => issuer + path;

        var configurations = new Dictionary<string, object>();
        foreach (var c in opts.VciCredentialConfigurations)
        {
            var entry = new Dictionary<string, object>
            {
                ["format"] = c.Format,
                ["credential_signing_alg_values_supported"] = c.CredentialSigningAlgValuesSupported,
                ["cryptographic_binding_methods_supported"] = c.CryptographicBindingMethodsSupported,
                ["proof_types_supported"] = c.ProofTypesSupported.ToDictionary(
                    kv => kv.Key,
                    kv => (object)new Dictionary<string, object> { ["proof_signing_alg_values_supported"] = kv.Value }),
            };
            if (c.Scope is not null) entry["scope"] = c.Scope;
            if (c.Vct is not null) entry["vct"] = c.Vct;
            configurations[c.Id] = entry;
        }

        var metadata = new Dictionary<string, object>
        {
            ["credential_issuer"] = issuer,
            ["credential_endpoint"] = Abs(opts.VciCredentialEndpoint),
            ["nonce_endpoint"] = Abs(opts.VciNonceEndpoint),
            ["credential_configurations_supported"] = configurations,
        };
        // A distinct credential issuer names this provider as its authorization server.
        if (issuer != opts.Issuer.TrimEnd('/'))
            metadata["authorization_servers"] = new[] { opts.Issuer.TrimEnd('/') };
        if (opts.RetrieveDeferredCredential is not null)
            metadata["deferred_credential_endpoint"] = Abs(opts.VciDeferredCredentialEndpoint);
        if (opts.OnCredentialNotification is not null)
            metadata["notification_endpoint"] = Abs(opts.VciNotificationEndpoint);
        if (opts.VciBatchSize > 1)
            metadata["batch_credential_issuance"] = new Dictionary<string, object> { ["batch_size"] = opts.VciBatchSize };
        return metadata;
    }

    /// <summary>The credential issuer identifier: <see cref="ProviderOptions.VciCredentialIssuer"/> or the issuer.</summary>
    public static string CredentialIssuer(ProviderOptions opts) =>
        (string.IsNullOrEmpty(opts.VciCredentialIssuer) ? opts.Issuer : opts.VciCredentialIssuer).TrimEnd('/');
}
