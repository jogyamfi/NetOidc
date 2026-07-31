using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Provider.DPoP;

/// <summary>
/// Validates DPoP proofs per RFC 9449 and computes JWK thumbprints (RFC 7638).
/// Thread-safe; maintains an in-process JTI replay cache.
/// </summary>
public sealed class DPopProofValidator
{
    // JTI → expiry; entries older than 2×clockSkew are pruned lazily.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _usedJtis = new();
    private readonly JsonWebTokenHandler _jwtHandler = new();

    private static readonly HashSet<string> SupportedAlgorithms =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "RS256", "RS384", "RS512",
            "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512",
        };

    /// <summary>
    /// Validates a DPoP proof header value.
    /// Returns the JWK thumbprint of the proof key on success, or <c>null</c> when the
    /// proof is missing or invalid.
    /// </summary>
    /// <param name="dpopHeader">Raw value of the <c>DPoP</c> HTTP header.</param>
    /// <param name="httpMethod">HTTP method of the protected request (e.g. "POST").</param>
    /// <param name="httpUri">Full URI of the request (query string is ignored per §4.3).</param>
    /// <param name="accessToken">
    /// When validating on a resource server, pass the raw access token so the <c>ath</c>
    /// claim can be checked.  Pass <c>null</c> on the token endpoint.
    /// </param>
    /// <param name="clockSkewSeconds">Allowed IAT drift (default 300 s).</param>
    public async Task<string?> ValidateProofAsync(
        string? dpopHeader,
        string httpMethod,
        string httpUri,
        string? accessToken = null,
        int clockSkewSeconds = 300)
    {
        if (string.IsNullOrEmpty(dpopHeader))
            return null;

        // Read the compact serialization without verifying the signature yet.
        JsonWebToken jwt;
        try { jwt = _jwtHandler.ReadJsonWebToken(dpopHeader); }
        catch { return null; }

        // typ MUST be "dpop+jwt" (RFC 9449 §4.2).
        if (!string.Equals(jwt.Typ, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
            return null;

        var alg = jwt.Alg;
        if (string.IsNullOrEmpty(alg) || alg == "none" || !SupportedAlgorithms.Contains(alg))
            return null;

        // Extract the embedded public JWK from the JOSE header.
        var jwk = ExtractJwkFromHeader(jwt.EncodedHeader);
        if (jwk is null || !string.IsNullOrEmpty(jwk.D))   // D present → private key leaked
            return null;

        // Cryptographically verify the proof using the embedded public key.
        var result = await _jwtHandler.ValidateTokenAsync(dpopHeader,
            new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,   // iat checked manually below
                IssuerSigningKey = jwk,
                ValidTypes = ["dpop+jwt"],
            });

        if (!result.IsValid)
            return null;

        var identity = result.ClaimsIdentity;

        // htm: HTTP method must match.
        var htm = identity.FindFirst("htm")?.Value;
        if (!string.Equals(htm, httpMethod, StringComparison.OrdinalIgnoreCase))
            return null;

        // htu: URI must match (query string stripped, RFC 9449 §4.3).
        var htu = identity.FindFirst("htu")?.Value;
        if (!UriMatches(htu, httpUri))
            return null;

        // iat: must be within the allowed window.
        var iatClaim = identity.FindFirst("iat")?.Value;
        if (!long.TryParse(iatClaim, out var iatUnix))
            return null;
        var iat = DateTimeOffset.FromUnixTimeSeconds(iatUnix);
        if (Math.Abs((DateTimeOffset.UtcNow - iat).TotalSeconds) > clockSkewSeconds)
            return null;

        // jti: must be present and not used before (replay prevention).
        var jti = identity.FindFirst("jti")?.Value;
        if (string.IsNullOrEmpty(jti))
            return null;
        var jtiExpiry = iat.AddSeconds(clockSkewSeconds * 2);
        if (!_usedJtis.TryAdd(jti, jtiExpiry))
            return null;    // replay detected
        PruneExpiredJtis();

        // ath: when an access token is supplied, the proof must commit to it.
        if (accessToken is not null)
        {
            var ath = identity.FindFirst("ath")?.Value;
            if (string.IsNullOrEmpty(ath) || ath != ComputeAth(accessToken))
                return null;
        }

        return ComputeJwkThumbprint(jwk);
    }

    // ── static helpers ─────────────────────────────────────────────────────────

    private static JsonWebKey? ExtractJwkFromHeader(string encodedHeader)
    {
        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(encodedHeader);
            using var doc = JsonDocument.Parse(bytes);
            if (!doc.RootElement.TryGetProperty("jwk", out var jwkEl))
                return null;
            return new JsonWebKey(jwkEl.GetRawText());
        }
        catch { return null; }
    }

    private static bool UriMatches(string? htu, string requestUri)
    {
        if (string.IsNullOrEmpty(htu)) return false;
        if (!Uri.TryCreate(htu, UriKind.Absolute, out var htuUri)) return false;
        if (!Uri.TryCreate(requestUri, UriKind.Absolute, out var reqUri)) return false;
        return string.Equals(
            htuUri.GetLeftPart(UriPartial.Path).TrimEnd('/'),
            reqUri.GetLeftPart(UriPartial.Path).TrimEnd('/'),
            StringComparison.OrdinalIgnoreCase);
    }

    private void PruneExpiredJtis()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kv in _usedJtis)
            if (kv.Value < now)
                _usedJtis.TryRemove(kv.Key, out _);
    }

    /// <summary>
    /// Computes the <c>ath</c> claim value:
    /// <c>BASE64URL(SHA-256(ASCII(access_token)))</c> per RFC 9449 §4.2.
    /// </summary>
    public static string ComputeAth(string accessToken) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));

    /// <summary>Computes the JWK thumbprint per RFC 7638 §3.</summary>
    public static string ComputeJwkThumbprint(JsonWebKey jwk)
    {
        // Only the required members, sorted lexicographically, no whitespace.
        string json = jwk.Kty switch
        {
            "EC" => JsonSerializer.Serialize(new
            {
                crv = jwk.Crv,
                kty = jwk.Kty,
                x = jwk.X,
                y = jwk.Y,
            }),
            "RSA" => JsonSerializer.Serialize(new
            {
                e = jwk.E,
                kty = jwk.Kty,
                n = jwk.N,
            }),
            _ => throw new NotSupportedException($"Unsupported key type for JWK thumbprint: {jwk.Kty}"),
        };
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    }

    /// <summary>
    /// Parses a JWK JSON string and returns its thumbprint; returns <c>null</c> on failure.
    /// </summary>
    public static string? ComputeThumbprintFromJwkJson(string jwkJson)
    {
        try { return ComputeJwkThumbprint(new JsonWebKey(jwkJson)); }
        catch { return null; }
    }
}
