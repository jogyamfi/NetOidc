using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Claims;

/// <summary>
/// Computes the effective subject identifier for a given user+client pair.
/// Supports "public" (pass-through) and "pairwise" (OIDC Core §8.1, RFC 8176) modes.
/// </summary>
public sealed class SubjectIdentifierService
{
    private readonly IOptions<ProviderOptions> _options;

    public SubjectIdentifierService(IOptions<ProviderOptions> options) => _options = options;

    /// <summary>
    /// Returns the subject to embed in tokens for the given raw <paramref name="subject"/>
    /// and <paramref name="clientId"/>. For pairwise mode, this is an opaque,
    /// per-client identifier (HMAC-SHA256 of sub + clientId + salt).
    /// </summary>
    public string Compute(string subject, string clientId)
    {
        var opts = _options.Value;
        if (!string.Equals(opts.SubjectType, "pairwise", StringComparison.OrdinalIgnoreCase))
            return subject;

        // Derive the HMAC key from the configured salt (or the issuer as fallback).
        var salt = opts.PairwiseSalt ?? opts.Issuer;
        var key = SHA256.HashData(Encoding.UTF8.GetBytes(salt));

        using var hmac = new HMACSHA256(key);
        var input = Encoding.UTF8.GetBytes(subject + "\x00" + clientId);
        var hash = hmac.ComputeHash(input);
        return Base64UrlEncoder.Encode(hash);
    }
}
