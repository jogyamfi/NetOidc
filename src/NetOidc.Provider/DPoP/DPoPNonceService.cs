using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.DPoP;

/// <summary>
/// Issues and checks DPoP server nonces (RFC 9449 §8). Nonces are stateless: an issue time
/// authenticated with HMAC-SHA256, so any instance sharing
/// <see cref="ProviderOptions.DPoPNonceSecret"/> accepts nonces issued by any other.
/// </summary>
public sealed class DPoPNonceService
{
    private const int TimestampBytes = 8;
    private const int MacBytes = 16;

    private readonly IOptions<ProviderOptions> _options;
    private readonly byte[] _key;

    public DPoPNonceService(IOptions<ProviderOptions> options)
    {
        _options = options;
        var secret = options.Value.DPoPNonceSecret;
        // Without a configured secret, nonces are only valid on this instance.
        _key = secret is null
            ? RandomNumberGenerator.GetBytes(32)
            : SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    }

    /// <summary>True when the provider requires DPoP proofs to carry a server nonce.</summary>
    public bool IsRequired => _options.Value.DPoPRequireNonce;

    /// <summary>Returns a fresh nonce.</summary>
    public string Issue()
    {
        Span<byte> buffer = stackalloc byte[TimestampBytes + MacBytes];
        BinaryPrimitives.WriteInt64BigEndian(buffer, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        Mac(buffer[..TimestampBytes]).AsSpan(0, MacBytes).CopyTo(buffer[TimestampBytes..]);
        return Base64UrlEncoder.Encode(buffer.ToArray());
    }

    /// <summary>True when <paramref name="nonce"/> was issued by this provider and is still fresh.</summary>
    public bool IsValid(string? nonce)
    {
        if (string.IsNullOrEmpty(nonce)) return false;

        byte[] bytes;
        try { bytes = Base64UrlEncoder.DecodeBytes(nonce); }
        catch (FormatException) { return false; }
        if (bytes.Length != TimestampBytes + MacBytes) return false;

        var expected = Mac(bytes.AsSpan(0, TimestampBytes)).AsSpan(0, MacBytes);
        if (!CryptographicOperations.FixedTimeEquals(expected, bytes.AsSpan(TimestampBytes)))
            return false;

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64BigEndian(bytes));
        var age = DateTimeOffset.UtcNow - issuedAt;
        return age >= TimeSpan.FromSeconds(-5) && age <= TimeSpan.FromSeconds(_options.Value.DPoPNonceLifetimeSeconds);
    }

    private byte[] Mac(ReadOnlySpan<byte> data) => HMACSHA256.HashData(_key, data);
}
