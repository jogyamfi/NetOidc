using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Vci;

/// <summary>
/// Manages c_nonce values for the credential endpoint (OID4VCI 1.0 §8.2).
/// Nonces are single-use and expire after <see cref="ProviderOptions.VciNonceLifetimeSeconds"/>.
/// </summary>
public sealed class VciService
{
    private sealed record NonceEntry(DateTimeOffset ExpiresAt);

    private readonly IOptions<ProviderOptions> _options;
    private readonly ConcurrentDictionary<string, NonceEntry> _nonces = new();

    public VciService(IOptions<ProviderOptions> options) => _options = options;

    /// <summary>Issues a new c_nonce and caches it for later validation.</summary>
    public string IssueNonce()
    {
        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        _nonces[nonce] = new NonceEntry(DateTimeOffset.UtcNow.AddSeconds(_options.Value.VciNonceLifetimeSeconds));
        return nonce;
    }

    /// <summary>
    /// Validates and consumes a c_nonce (single-use).
    /// Returns true when the nonce is known and not expired.
    /// </summary>
    public bool ConsumeNonce(string nonce)
    {
        if (!_nonces.TryRemove(nonce, out var entry))
            return false;
        return entry.ExpiresAt > DateTimeOffset.UtcNow;
    }

    public int NonceLifetimeSeconds => _options.Value.VciNonceLifetimeSeconds;
}
