using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Adapters;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Vci;

/// <summary>
/// Manages c_nonce values for the credential endpoint (OID4VCI 1.0 §8.2).
/// Nonces are single-use and expire after <see cref="ProviderOptions.VciNonceLifetimeSeconds"/>;
/// expired ones are swept by the underlying store.
/// </summary>
public sealed class VciService
{
    private sealed record NonceEntry;

    private readonly IOptions<ProviderOptions> _options;
    private readonly InMemoryAdapter<NonceEntry> _nonces = new();

    public VciService(IOptions<ProviderOptions> options) => _options = options;

    /// <summary>Issues a new c_nonce and caches it for later validation.</summary>
    public string IssueNonce()
    {
        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        _nonces.StoreAsync(nonce, new NonceEntry(), TimeSpan.FromSeconds(NonceLifetimeSeconds));
        return nonce;
    }

    /// <summary>
    /// Validates and consumes a c_nonce (single-use).
    /// Returns true when the nonce is known and not expired.
    /// </summary>
    public bool ConsumeNonce(string nonce) =>
        _nonces.ConsumeAsync(nonce).GetAwaiter().GetResult() is not null;

    public int NonceLifetimeSeconds => _options.Value.VciNonceLifetimeSeconds;
}
