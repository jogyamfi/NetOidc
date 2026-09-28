using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.Jose;

/// <summary>Reads the public key a proof JWT carries in its JOSE header (<c>jwk</c> member).</summary>
internal static class EmbeddedJwk
{
    /// <summary>
    /// Returns the header's <c>jwk</c> and its raw JSON, or <c>null</c> when it is absent,
    /// malformed, or contains private key material.
    /// </summary>
    public static (JsonWebKey Key, string Json)? FromHeader(string encodedHeader)
    {
        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(encodedHeader);
            using var doc = JsonDocument.Parse(bytes);
            if (!doc.RootElement.TryGetProperty("jwk", out var jwkEl) ||
                jwkEl.ValueKind != JsonValueKind.Object)
                return null;

            var json = jwkEl.GetRawText();
            var key = new JsonWebKey(json);
            // A private component means the key is compromised; never accept it.
            if (!string.IsNullOrEmpty(key.D) || !string.IsNullOrEmpty(key.K))
                return null;
            return (key, json);
        }
        catch
        {
            return null;
        }
    }
}
