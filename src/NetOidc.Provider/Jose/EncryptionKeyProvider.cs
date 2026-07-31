using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Jose;

/// <summary>RSA public encryption key in JWK format (use=enc).</summary>
public sealed class RsaEncPublicJwk
{
    [JsonPropertyName("kty")] public required string Kty { get; init; }
    [JsonPropertyName("use")] public required string Use { get; init; }
    [JsonPropertyName("alg")] public required string Alg { get; init; }
    [JsonPropertyName("kid")] public required string Kid { get; init; }
    [JsonPropertyName("n")] public required string N { get; init; }
    [JsonPropertyName("e")] public required string E { get; init; }
}

/// <summary>
/// Holds the provider's RSA encryption key pair (use=enc, RSA-OAEP-256 / A256GCM).
/// Used to decrypt incoming encrypted JAR request objects.
/// Auto-generates a 2048-bit RSA key on first use; replace for production.
/// </summary>
public sealed class EncryptionKeyProvider : IDisposable
{
    private readonly RSA _rsa;
    private readonly string _kid;
    private readonly RsaSecurityKey _securityKey;

    public EncryptionKeyProvider()
    {
        _rsa = RSA.Create(2048);
        _kid = "enc-" + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));
        _securityKey = new RsaSecurityKey(_rsa) { KeyId = _kid };
    }

    /// <summary>Returns decryption credentials for incoming JWE request objects.</summary>
    public SecurityKey GetDecryptionKey() => _securityKey;

    /// <summary>Returns the public-key JWK to include in JWKS endpoint (use=enc).</summary>
    public RsaEncPublicJwk GetPublicJwk()
    {
        var p = _rsa.ExportParameters(includePrivateParameters: false);
        return new RsaEncPublicJwk
        {
            Kty = "RSA",
            Use = "enc",
            Alg = "RSA-OAEP-256",
            Kid = _kid,
            N = Base64UrlEncoder.Encode(p.Modulus!),
            E = Base64UrlEncoder.Encode(p.Exponent!),
        };
    }

    public void Dispose() => _rsa.Dispose();
}
