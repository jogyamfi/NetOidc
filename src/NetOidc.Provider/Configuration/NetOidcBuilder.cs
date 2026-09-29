using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Events;

namespace NetOidc.Provider.Configuration;

/// <summary>
/// Fluent builder returned by AddNetOidc(). Future phases attach
/// extension methods (e.g. AddInMemoryClients, UseEfCoreAdapters).
/// </summary>
public sealed class NetOidcBuilder
{
    public IServiceCollection Services { get; }

    internal NetOidcBuilder(IServiceCollection services) => Services = services;

    // ── Keys ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Adds a signing key (RSA for RS*/PS*, EC for ES*). Register the successor of a key with a
    /// future <paramref name="notBefore"/> to publish it ahead of use, and give the old key a
    /// <paramref name="notAfter"/> after the last token it signed has expired.
    /// </summary>
    public NetOidcBuilder AddSigningKey(
        Microsoft.IdentityModel.Tokens.SecurityKey key, string algorithm = "RS256",
        DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, string? keyId = null) =>
        AddKey(new Jose.ProviderKey
        {
            Key = key,
            Algorithm = algorithm,
            Use = Jose.ProviderKeyUse.Signing,
            NotBefore = notBefore,
            NotAfter = notAfter,
            ExplicitKeyId = keyId,
        });

    /// <summary>
    /// Adds a signing certificate; its chain is published as <c>x5c</c>. Validity defaults to
    /// the certificate's own validity period.
    /// </summary>
    public NetOidcBuilder AddSigningCertificate(
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate, string algorithm = "RS256",
        DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null) =>
        AddKey(new Jose.ProviderKey
        {
            Key = new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate),
            Algorithm = algorithm,
            Use = Jose.ProviderKeyUse.Signing,
            NotBefore = notBefore ?? new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
            NotAfter = notAfter ?? new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
        });

    /// <summary>Adds an RSA key used to decrypt request objects encrypted to the provider.</summary>
    public NetOidcBuilder AddEncryptionKey(
        Microsoft.IdentityModel.Tokens.SecurityKey key, string algorithm = "RSA-OAEP-256",
        DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, string? keyId = null) =>
        AddKey(new Jose.ProviderKey
        {
            Key = key,
            Algorithm = algorithm,
            Use = Jose.ProviderKeyUse.Encryption,
            NotBefore = notBefore,
            NotAfter = notAfter,
            ExplicitKeyId = keyId,
        });

    /// <summary>Adds a fully described key (e.g. an HSM/KMS key with an explicit public JWK).</summary>
    public NetOidcBuilder AddKey(Jose.ProviderKey key)
    {
        Services.Configure<ProviderOptions>(o => o.Keys.Add(key));
        return this;
    }

    /// <summary>
    /// Replaces the key source, e.g. with a vault/HSM/KMS-backed <see cref="Jose.IKeyStore"/>.
    /// </summary>
    public NetOidcBuilder UseKeyStore<T>() where T : class, Jose.IKeyStore
    {
        Services.AddSingleton<Jose.IKeyStore, T>();
        return this;
    }

    /// <summary>
    /// Replaces the default no-op event sink with a custom implementation.
    /// </summary>
    public NetOidcBuilder AddEventSink<T>() where T : class, IProviderEventSink
    {
        // Replace the no-op default.
        Services.AddSingleton<IProviderEventSink, T>();
        return this;
    }

    /// <summary>
    /// Applies the specified FAPI compliance profile. When <paramref name="validate"/>
    /// is <c>true</c>, the provider validates the full <see cref="ProviderOptions"/>
    /// graph against the profile constraints at startup (via
    /// <see cref="IValidateOptions{TOptions}"/>).
    /// </summary>
    public NetOidcBuilder UseFapiProfile(FapiProfile profile, bool validate = false)
    {
        Services.PostConfigure<ProviderOptions>(opts =>
        {
            opts.FapiProfile = profile;
            opts.FapiProfileValidationEnabled = validate;
        });
        return this;
    }
}
