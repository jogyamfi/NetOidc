using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Jose;

/// <summary>RSA public key in JWK format (safe to expose in /.well-known/jwks.json).</summary>
public sealed class RsaPublicJwk
{
    [JsonPropertyName("kty")] public required string Kty { get; init; }
    [JsonPropertyName("use")] public required string Use { get; init; }
    [JsonPropertyName("alg")] public required string Alg { get; init; }
    [JsonPropertyName("kid")] public required string Kid { get; init; }
    [JsonPropertyName("n")] public required string N { get; init; }
    [JsonPropertyName("e")] public required string E { get; init; }
}

/// <summary>
/// Holds the provider's long-lived RS256 signing key. Auto-generates a 2048-bit RSA key
/// on first use. Replace with a configured key for production deployments.
/// </summary>
public sealed class SigningKeyProvider : IDisposable
{
    private readonly RSA _rsa;
    private readonly string _kid;
    private readonly RsaSecurityKey _securityKey;

    public SigningKeyProvider()
    {
        _rsa = RSA.Create(2048);
        _kid = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));
        _securityKey = new RsaSecurityKey(_rsa) { KeyId = _kid };
    }

    public SigningCredentials GetSigningCredentials() =>
        new(_securityKey, SecurityAlgorithms.RsaSha256);

    /// <summary>Returns the key used to validate tokens (public + private; used internally only).</summary>
    public SecurityKey GetValidationKey() => _securityKey;

    /// <summary>Returns the public-key-only JWK for the JWKS endpoint.</summary>
    public RsaPublicJwk GetPublicJwk()
    {
        var p = _rsa.ExportParameters(includePrivateParameters: false);
        return new RsaPublicJwk
        {
            Kty = "RSA",
            Use = "sig",
            Alg = "RS256",
            Kid = _kid,
            N = Base64UrlEncoder.Encode(p.Modulus!),
            E = Base64UrlEncoder.Encode(p.Exponent!),
        };
    }

    public void Dispose() => _rsa.Dispose();
}
