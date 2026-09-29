using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Authorization;

/// <summary>Validates PKCE (RFC 7636) code_verifier against a stored code_challenge.</summary>
internal static class PkceValidator
{
    /// <summary>
    /// Returns <c>true</c> when <paramref name="value"/> is 43–128 characters from the unreserved
    /// set <c>[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"</c> (RFC 7636 §4.1, §4.2).
    /// </summary>
    public static bool IsWellFormed(string value) =>
        value.Length is >= 43 and <= 128 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~');

    /// <summary>
    /// Returns <c>true</c> when <paramref name="codeVerifier"/> is well formed and satisfies
    /// <paramref name="codeChallenge"/> for the given <paramref name="method"/>.
    /// </summary>
    public static bool Validate(string codeVerifier, string codeChallenge, string method)
    {
        if (!IsWellFormed(codeVerifier))
            return false;

        if (method.Equals("S256", StringComparison.Ordinal))
        {
            var hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(codeVerifier));
            var expected = Base64UrlEncoder.Encode(hash);
            return CryptographicEquals(expected, codeChallenge);
        }

        // plain
        return CryptographicEquals(codeVerifier, codeChallenge);
    }

    private static bool CryptographicEquals(string a, string b)
    {
        var bytesA = System.Text.Encoding.UTF8.GetBytes(a);
        var bytesB = System.Text.Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }
}
