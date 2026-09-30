using Microsoft.Extensions.Hosting;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Jose;

/// <summary>
/// Default <see cref="IKeyStore"/>: the keys registered in <see cref="ProviderOptions.Keys"/>
/// (see <c>NetOidcBuilder.AddSigningKey</c> and friends). When no signing key (or, outside
/// Production, no encryption key) is configured, an RSA key is generated for the lifetime of the
/// process — acceptable for development only; production hosts refuse to start with generated keys.
/// </summary>
internal sealed class ConfiguredKeyStore : IKeyStore, IDisposable
{
    private readonly IReadOnlyList<ProviderKey> _keys;
    private readonly List<IDisposable> _generated = [];

    public ConfiguredKeyStore(IOptions<ProviderOptions> options, IHostEnvironment? environment = null)
    {
        var keys = options.Value.Keys.ToList();

        if (!keys.Any(k => k.Use == ProviderKeyUse.Signing))
            keys.Add(Generate(ProviderKeyUse.Signing, SecurityAlgorithms.RsaSha256));
        // Encryption keys are optional: without one, encrypted request objects are simply not
        // offered. Generating one in Production would only make the startup check refuse to start.
        if (!keys.Any(k => k.Use == ProviderKeyUse.Encryption) && environment?.IsProduction() != true)
            keys.Add(Generate(ProviderKeyUse.Encryption, "RSA-OAEP"));
        if (options.Value.FederationEnabled && !keys.Any(k => k.Use == ProviderKeyUse.Federation))
            keys.Add(Generate(ProviderKeyUse.Federation, SecurityAlgorithms.RsaSha256));

        _keys = keys;
    }

    public IReadOnlyList<ProviderKey> GetKeys() => _keys;

    private ProviderKey Generate(ProviderKeyUse use, string algorithm)
    {
        var rsa = RSA.Create(2048);
        _generated.Add(rsa);
        var prefix = use switch
        {
            ProviderKeyUse.Encryption => "enc-",
            ProviderKeyUse.Federation => "fed-",
            _ => string.Empty,
        };
        return new ProviderKey
        {
            Key = new RsaSecurityKey(rsa) { KeyId = prefix + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)) },
            Algorithm = algorithm,
            Use = use,
            IsGenerated = true,
        };
    }

    public void Dispose()
    {
        foreach (var d in _generated) d.Dispose();
    }
}
