using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Jose;

/// <summary>
/// Validates the key configuration when the host starts: Production hosts must use configured
/// keys (generated keys disappear on restart and differ per instance), every key must use a
/// supported algorithm that matches its key type, key ids must be unique, and at least one
/// signing key must be active.
/// </summary>
internal sealed class KeyRingStartupCheck : IHostedService
{
    private readonly IKeyStore _store;
    private readonly KeyRing _keys;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<KeyRingStartupCheck> _logger;

    public KeyRingStartupCheck(IKeyStore store, KeyRing keys, IHostEnvironment environment, ILogger<KeyRingStartupCheck> logger)
    {
        _store = store;
        _keys = keys;
        _environment = environment;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var errors = Validate(_store.GetKeys(), DateTimeOffset.UtcNow).ToList();

        if (_keys.HasGeneratedKeys)
        {
            if (_environment.IsProduction())
                errors.Add("No signing/encryption keys are configured and generated keys are not allowed in " +
                           "Production. Register keys with AddSigningKey/AddSigningCertificate/AddEncryptionKey " +
                           "or UseKeyStore<T>().");
            else
                _logger.LogWarning("NetOidc is using generated keys; tokens will not survive a restart. " +
                                   "Configure keys before deploying.");
        }

        if (errors.Count > 0)
            throw new InvalidOperationException("Invalid NetOidc key configuration:\n  " + string.Join("\n  ", errors));

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    internal static IEnumerable<string> Validate(IReadOnlyList<ProviderKey> keys, DateTimeOffset now)
    {
        if (!keys.Any(k => k.Use == ProviderKeyUse.Signing && k.IsActive(now)))
            yield return "There is no active signing key.";

        foreach (var group in keys.GroupBy(k => k.KeyId).Where(g => g.Count() > 1))
            yield return $"Key id '{group.Key}' is used by more than one key.";

        foreach (var key in keys)
        {
            var supported = key.Use == ProviderKeyUse.Encryption
                ? KeyRing.SupportedEncryptionAlgorithms
                : KeyRing.SupportedSigningAlgorithms;
            if (!supported.Contains(key.Algorithm))
            {
                yield return $"Key '{key.KeyId}' uses unsupported {key.Use.ToString().ToLowerInvariant()} algorithm '{key.Algorithm}'.";
                continue;
            }

            if (key.NotBefore is { } nbf && key.NotAfter is { } naf && naf <= nbf)
                yield return $"Key '{key.KeyId}' has NotAfter before NotBefore.";

            if (KeyTypeError(key) is { } typeError)
                yield return typeError;
        }
    }

    /// <summary>RS*/PS*/RSA-OAEP need an RSA key; ES256/384/512 need P-256/P-384/P-521.</summary>
    private static string? KeyTypeError(ProviderKey key)
    {
        // Keys backed by a custom crypto provider (HSM/KMS) are trusted to match their algorithm.
        if (key.PublicJwk is not null) return null;

        var (isRsa, curveBits) = key.Key switch
        {
            RsaSecurityKey => (true, 0),
            ECDsaSecurityKey ec => (false, ec.ECDsa.KeySize),
            X509SecurityKey x509 => x509.Certificate.GetRSAPublicKey() is { } rsa
                ? Dispose(rsa, (true, 0))
                : x509.Certificate.GetECDsaPublicKey() is { } ecdsa ? Dispose(ecdsa, (false, ecdsa.KeySize)) : (false, -1),
            JsonWebKey jwk => (jwk.Kty == "RSA", jwk.Kty == "EC" ? CurveBits(jwk.Crv) : 0),
            _ => (false, -1),
        };

        var wanted = key.Algorithm switch
        {
            "ES256" => 256,
            "ES384" => 384,
            "ES512" => 521,
            _ => 0,
        };

        return wanted == 0
            ? isRsa ? null : $"Key '{key.KeyId}' must be an RSA key for {key.Algorithm}."
            : !isRsa && curveBits == wanted ? null : $"Key '{key.KeyId}' must be an EC key on the matching curve for {key.Algorithm}.";

        static (bool, int) Dispose(IDisposable d, (bool, int) value)
        {
            d.Dispose();
            return value;
        }

        static int CurveBits(string? crv) => crv switch { "P-256" => 256, "P-384" => 384, "P-521" => 521, _ => -1 };
    }
}
