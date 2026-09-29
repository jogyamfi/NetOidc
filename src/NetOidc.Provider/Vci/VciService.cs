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
public sealed class VciService
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
}
