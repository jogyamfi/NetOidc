using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Token;

/// <summary>
/// Extracts and validates client credentials from an HTTP request.
/// Supports: client_secret_basic, client_secret_post, private_key_jwt,
/// client_secret_jwt, tls_client_auth, self_signed_tls_client_auth.
/// </summary>
internal static class ClientAuthenticator
{
    private const string JwtBearerAssertionType =
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static readonly JsonWebTokenHandler JwtHandler = new();

    public static async Task<Client?> AuthenticateAsync(
        HttpContext context,
        IFormCollection form,
        IClientStore clientStore,
        ProviderOptions opts,
        CancellationToken ct)
    {
        // ── 1. HTTP Basic → client_secret_basic ────────────────────────────
        var (basicId, basicSecret) = TryParseBasicAuth(context);
        if (basicId is not null)
        {
            var client = await clientStore.FindClientAsync(basicId, ct);
            if (client?.TokenEndpointAuthMethod == "client_secret_basic" &&
                client.ClientSecret is not null &&
                ConstantTimeEquals(basicSecret ?? string.Empty, client.ClientSecret))
                return client;
            return null;
        }

        var assertionType = form["client_assertion_type"].ToString();
        var assertion = form["client_assertion"].ToString();

        // ── 2. JWT client assertion (private_key_jwt / client_secret_jwt) ──
        if (assertionType == JwtBearerAssertionType && !string.IsNullOrEmpty(assertion))
            return await AuthenticateJwtAssertionAsync(assertion, form, clientStore, opts, ct);

        // ── 3. mTLS (tls_client_auth / self_signed_tls_client_auth) ────────
        if (opts.MtlsEnabled)
        {
            var cert = GetClientCertificate(context, opts);
            if (cert is not null)
            {
                var mtlsClientId = form["client_id"].ToString();
                if (!string.IsNullOrEmpty(mtlsClientId))
                {
                    var client = await clientStore.FindClientAsync(mtlsClientId, ct);
                    if (client is not null)
                    {
                        if (client.TokenEndpointAuthMethod == "tls_client_auth" &&
                            ValidateTlsClientAuth(cert, client))
                            return client;
                        if (client.TokenEndpointAuthMethod == "self_signed_tls_client_auth" &&
                            ValidateSelfSignedTlsClientAuth(cert, client))
                            return client;
                    }
                }
                return null;
            }
        }

        // ── 4. Form body → client_secret_post ──────────────────────────────
        var formId = form["client_id"].ToString();
        if (!string.IsNullOrEmpty(formId))
        {
            var client = await clientStore.FindClientAsync(formId, ct);
            var formSecret = form["client_secret"].ToString();
            if (client?.TokenEndpointAuthMethod == "client_secret_post" &&
                client.ClientSecret is not null &&
                ConstantTimeEquals(formSecret, client.ClientSecret))
                return client;
            return null;
        }

        return null;
    }

    // ── JWT assertion validation ───────────────────────────────────────────────

    private static async Task<Client?> AuthenticateJwtAssertionAsync(
        string assertion,
        IFormCollection form,
        IClientStore clientStore,
        ProviderOptions opts,
        CancellationToken ct)
    {
        // Read without validating to identify the client from iss/sub.
        JsonWebToken unvalidated;
        try { unvalidated = JwtHandler.ReadJsonWebToken(assertion); }
        catch { return null; }

        var clientId = unvalidated.Issuer
            ?? unvalidated.Subject
            ?? form["client_id"].ToString();
        if (string.IsNullOrEmpty(clientId))
            return null;

        var client = await clientStore.FindClientAsync(clientId, ct);
        if (client is null) return null;

        // aud must be the token endpoint URL or issuer.
        var issuer = opts.Issuer.TrimEnd('/');
        var tokenEndpoint = issuer + opts.TokenEndpoint;
        var validAudiences = new[] { tokenEndpoint, issuer };

        switch (client.TokenEndpointAuthMethod)
        {
            case "private_key_jwt":
            {
                if (client.JwksJson is null) return null;
                var jwks = new JsonWebKeySet(client.JwksJson);
                foreach (var key in jwks.Keys)
                {
                    var result = await JwtHandler.ValidateTokenAsync(assertion,
                        new TokenValidationParameters
                        {
                            ValidIssuer = clientId,
                            ValidAudiences = validAudiences,
                            IssuerSigningKey = key,
                            ValidateLifetime = true,
                            ClockSkew = TimeSpan.FromSeconds(30),
                        });
                    if (result.IsValid) return client;
                }
                return null;
            }

            case "client_secret_jwt":
            {
                if (client.ClientSecret is null) return null;
                var secretBytes = System.Text.Encoding.UTF8.GetBytes(client.ClientSecret);
                // Pad or truncate to a valid HMAC key length.
                var keyMaterial = secretBytes.Length >= 32
                    ? secretBytes
                    : SHA256.HashData(secretBytes);
                var hmacKey = new SymmetricSecurityKey(keyMaterial);
                var result = await JwtHandler.ValidateTokenAsync(assertion,
                    new TokenValidationParameters
                    {
                        ValidIssuer = clientId,
                        ValidAudiences = validAudiences,
                        IssuerSigningKey = hmacKey,
                        ValidAlgorithms = ["HS256", "HS384", "HS512"],
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromSeconds(30),
                    });
                return result.IsValid ? client : null;
            }

            default:
                return null;
        }
    }

    // ── mTLS helpers ──────────────────────────────────────────────────────────

    internal static X509Certificate2? GetClientCertificate(
        HttpContext context, ProviderOptions opts)
    {
        if (opts.MtlsClientCertificateHeader is not null)
        {
            var header = context.Request.Headers[opts.MtlsClientCertificateHeader].ToString();
            if (!string.IsNullOrEmpty(header))
            {
                try
                {
                    // Header value may be URL-encoded PEM.
                    var pem = Uri.UnescapeDataString(header);
                    return X509Certificate2.CreateFromPem(pem);
                }
                catch { return null; }
            }
        }

        return context.Connection.ClientCertificate as X509Certificate2;
    }

    private static bool ValidateTlsClientAuth(X509Certificate2 cert, Client client)
    {
        // At least one of the configured fields must match.
        if (client.TlsClientAuthSubjectDn is not null &&
            string.Equals(cert.Subject, client.TlsClientAuthSubjectDn,
                StringComparison.OrdinalIgnoreCase))
            return true;

        if (client.TlsClientAuthSanDns is not null &&
            HasSanDns(cert, client.TlsClientAuthSanDns))
            return true;

        if (client.TlsClientAuthSanUri is not null &&
            HasSanUri(cert, client.TlsClientAuthSanUri))
            return true;

        if (client.TlsClientAuthSanIp is not null &&
            HasSanIp(cert, client.TlsClientAuthSanIp))
            return true;

        return false;
    }

    private static bool ValidateSelfSignedTlsClientAuth(X509Certificate2 cert, Client client)
    {
        if (client.JwksJson is null) return false;
        try
        {
            var jwks = new JsonWebKeySet(client.JwksJson);
            var certThumbprint = ComputeCertThumbprint(cert);
            foreach (var key in jwks.Keys)
            {
                // Match by x5t#S256 if present in the JWK.
                if (key.X5t is not null)
                {
                    // x5t is SHA-1; check x5tS256 via the extension, or fall back to public-key match.
                }
                // Match by comparing the public key.
                if (PublicKeyMatchesCert(key, cert)) return true;
            }
        }
        catch { /* Malformed JWKS */ }
        return false;
    }

    private static bool PublicKeyMatchesCert(JsonWebKey key, X509Certificate2 cert)
    {
        try
        {
            if (key.Kty == "RSA")
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Base64UrlEncoder.DecodeBytes(key.N),
                    Exponent = Base64UrlEncoder.DecodeBytes(key.E),
                });
                using var certRsa = cert.GetRSAPublicKey();
                if (certRsa is null) return false;
                var keyParams = rsa.ExportParameters(false);
                var certParams = certRsa.ExportParameters(false);
                return keyParams.Modulus!.SequenceEqual(certParams.Modulus!);
            }

            if (key.Kty == "EC")
            {
                using var certEc = cert.GetECDsaPublicKey();
                if (certEc is null) return false;
                var certParams = certEc.ExportParameters(false);
                var certX = Base64UrlEncoder.Encode(certParams.Q.X!);
                var certY = Base64UrlEncoder.Encode(certParams.Q.Y!);
                return string.Equals(key.X, certX) && string.Equals(key.Y, certY);
            }
        }
        catch { /* mismatch */ }
        return false;
    }

    // ── Certificate thumbprint ─────────────────────────────────────────────────

    /// <summary>
    /// Computes the SHA-256 thumbprint of a certificate DER encoding,
    /// base64url-encoded per RFC 8705 §3.
    /// </summary>
    internal static string ComputeCertThumbprint(X509Certificate2 cert) =>
        Base64UrlEncoder.Encode(cert.GetCertHash(HashAlgorithmName.SHA256));

    // ── SAN helpers ────────────────────────────────────────────────────────────

    private static bool HasSanDns(X509Certificate2 cert, string expected)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension san)
            {
                foreach (var name in san.EnumerateDnsNames())
                    if (string.Equals(name, expected, StringComparison.OrdinalIgnoreCase))
                        return true;
            }
        }
        return false;
    }

    private static bool HasSanUri(X509Certificate2 cert, string expected)
    {
        // X509SubjectAlternativeNameExtension.EnumerateUris() is .NET 9+.
        // Fallback: use GetNameInfo for the first URI SAN.
        var uri = cert.GetNameInfo(X509NameType.UrlName, forIssuer: false);
        return !string.IsNullOrEmpty(uri) &&
               string.Equals(uri, expected, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSanIp(X509Certificate2 cert, string expected)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension san)
            {
                foreach (var ip in san.EnumerateIPAddresses())
                    if (string.Equals(ip.ToString(), expected, StringComparison.OrdinalIgnoreCase))
                        return true;
            }
        }
        return false;
    }

    // ── Shared helpers ─────────────────────────────────────────────────────────

    private static (string? Id, string? Secret) TryParseBasicAuth(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return (null, null);

        try
        {
            var decoded = System.Text.Encoding.UTF8.GetString(
                Convert.FromBase64String(header["Basic ".Length..].Trim()));
            var colon = decoded.IndexOf(':');
            if (colon < 0) return (null, null);
            // RFC 6749 §2.3.1: client_id and secret are URL-encoded.
            return (Uri.UnescapeDataString(decoded[..colon]),
                    Uri.UnescapeDataString(decoded[(colon + 1)..]));
        }
        catch
        {
            return (null, null);
        }
    }

    private static bool ConstantTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(a),
            System.Text.Encoding.UTF8.GetBytes(b));
}
