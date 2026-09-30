using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Jose;

/// <summary>What a provider key is used for.</summary>
public enum ProviderKeyUse
{
    /// <summary>Signs ID tokens, access tokens, JARM responses, logout tokens, …</summary>
    Signing,

    /// <summary>Decrypts encrypted request objects sent to the provider.</summary>
    Encryption,

    /// <summary>Signs OpenID Federation entity statements (kept apart from token signing keys).</summary>
    Federation,
}

/// <summary>
/// A key the provider signs or decrypts with. Keys are published in the JWKS while they are
/// not expired; signing keys are used from <see cref="NotBefore"/>, which allows a new key to
/// be published ahead of activation and an old key to stay verifiable after its successor
/// takes over (rotation with overlap).
/// </summary>
public sealed class ProviderKey
{
    /// <summary>
    /// The key. For HSM/KMS keys supply a <see cref="SecurityKey"/> whose
    /// <see cref="SecurityKey.CryptoProviderFactory"/> delegates signing or decryption to the
    /// device, together with <see cref="PublicJwk"/>.
    /// </summary>
    public required SecurityKey Key { get; init; }

    /// <summary>JWA algorithm: RS256…PS512, ES256…ES512 for signing; RSA-OAEP for encryption.</summary>
    public required string Algorithm { get; init; }

    public ProviderKeyUse Use { get; init; } = ProviderKeyUse.Signing;

    /// <summary>Key id (<c>kid</c>). Defaults to the key's own id or its RFC 7638 thumbprint.</summary>
    public string KeyId => _keyId ??= ResolveKeyId();
    private string? _keyId;

    /// <summary>Set to fix the <c>kid</c> explicitly.</summary>
    public string? ExplicitKeyId { get; init; }

    /// <summary>Not used for signing before this time (still published).</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>Neither used nor published after this time.</summary>
    public DateTimeOffset? NotAfter { get; init; }

    /// <summary>
    /// Public JWK to publish. Required when the private key material is not accessible
    /// (HSM/KMS); otherwise derived from <see cref="Key"/>.
    /// </summary>
    public JsonWebKey? PublicJwk { get; init; }

    /// <summary>True for keys the provider generated itself because none were configured.</summary>
    public bool IsGenerated { get; init; }

    /// <summary>True while the key may be published and used to verify or decrypt.</summary>
    public bool IsPublished(DateTimeOffset now) => NotAfter is null || NotAfter > now;

    /// <summary>True while the key may be used to sign or decrypt.</summary>
    public bool IsActive(DateTimeOffset now) => IsPublished(now) && (NotBefore is null || NotBefore <= now);

    private string ResolveKeyId()
    {
        if (!string.IsNullOrEmpty(ExplicitKeyId)) return ExplicitKeyId;
        if (!string.IsNullOrEmpty(Key.KeyId)) return Key.KeyId;
        if (PublicJwk?.Kid is { Length: > 0 } kid) return kid;
        try
        {
            return Base64UrlEncoder.Encode(Key.ComputeJwkThumbprint());
        }
        catch (Exception ex) when (ex is NotSupportedException or CryptographicException or InvalidOperationException)
        {
            return Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));
        }
    }
}

/// <summary>
/// Supplies the provider's keys. Implement this to source keys from a vault, HSM or KMS; the
/// provider calls <see cref="GetKeys"/> on every use, so implementations should cache.
/// </summary>
public interface IKeyStore
{
    IReadOnlyList<ProviderKey> GetKeys();
}
