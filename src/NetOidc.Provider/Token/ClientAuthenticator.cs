using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
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
public sealed class ClientAuthenticator
{
    private const string JwtBearerAssertionType =
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    /// <summary>Asymmetric algorithms accepted for <c>private_key_jwt</c>.</summary>
    private static readonly string[] AsymmetricAlgorithms =
        ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    /// <summary>HMAC algorithms for <c>client_secret_jwt</c> and the minimum key size each needs (RFC 7518 §3.2).</summary>
    private static readonly Dictionary<string, int> HmacMinKeyBytes = new()
    {
        ["HS256"] = 32,
        ["HS384"] = 48,
        ["HS512"] = 64,
    };

    private readonly IClientStore _clientStore;
    private readonly IOptions<ProviderOptions> _options;
    private readonly IReplayCache _replayCache;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    public ClientAuthenticator(
        IClientStore clientStore, IOptions<ProviderOptions> options, IReplayCache replayCache)
    {
        _clientStore = clientStore;
        _options = options;
        _replayCache = replayCache;
    }

    /// <summary>
    /// Authenticates the calling client, or returns <c>null</c> (→ <c>invalid_client</c>).
    /// </summary>
    public async Task<Client?> AuthenticateAsync(
        HttpContext context, IFormCollection form, CancellationToken ct)
    {
        var opts = _options.Value;
        var client = await AuthenticateCoreAsync(context, form, opts, ct);
        if (client is null) return null;

        // FAPI 2.0: only private_key_jwt and mTLS methods are allowed (§5.3.1).
        var isFapi2 = opts.FapiProfile is FapiProfile.Fapi2Security
            or FapiProfile.Fapi2MessageSigning
            or FapiProfile.FapiCiba;
        if (isFapi2 && client.TokenEndpointAuthMethod is not
                ("private_key_jwt" or "tls_client_auth" or "self_signed_tls_client_auth"))
            return null;

        // FAPI 1.0 Advanced §5.2.2 (final): confidential clients using private_key_jwt or mTLS only.
        if (opts.FapiProfile == FapiProfile.Fapi1Advanced && client.TokenEndpointAuthMethod is not
                ("private_key_jwt" or "tls_client_auth" or "self_signed_tls_client_auth"))
            return null;

        return client;
    }

    private async Task<Client?> AuthenticateCoreAsync(
        HttpContext context, IFormCollection form, ProviderOptions opts, CancellationToken ct)
    {
        var (basicId, basicSecret) = TryParseBasicAuth(context);
        var hasBasic = basicId is not null;
        var hasFormSecret = !string.IsNullOrEmpty(form["client_secret"].ToString());
        var assertion = form["client_assertion"].ToString();
        var hasAssertion = !string.IsNullOrEmpty(assertion) ||
                           !string.IsNullOrEmpty(form["client_assertion_type"].ToString());
        var formClientId = form["client_id"].ToString();

        // RFC 6749 §2.3: a client MUST NOT use more than one authentication method per request.
        if ((hasBasic ? 1 : 0) + (hasFormSecret ? 1 : 0) + (hasAssertion ? 1 : 0) > 1)
            return null;

        // ── client_secret_basic ─────────────────────────────────────────────
        if (hasBasic)
        {
            if (!string.IsNullOrEmpty(formClientId) && formClientId != basicId)
                return null;
            var client = await _clientStore.FindClientAsync(basicId!, ct);
            return client?.TokenEndpointAuthMethod == "client_secret_basic" &&
                   client.ClientSecret is not null &&
                   ConstantTimeEquals(basicSecret ?? string.Empty, client.ClientSecret)
                ? client : null;
        }

        // ── private_key_jwt / client_secret_jwt ─────────────────────────────
        if (hasAssertion)
        {
            if (form["client_assertion_type"].ToString() != JwtBearerAssertionType || string.IsNullOrEmpty(assertion))
                return null;
            // RFC 9126 §2: the PAR endpoint URL is also an acceptable audience.
            var endpointUrl = opts.Issuer.TrimEnd('/') + context.Request.Path.Value;
            return await AuthenticateJwtAssertionAsync(assertion, formClientId, opts, endpointUrl, ct);
        }

        if (string.IsNullOrEmpty(formClientId))
            return null;

        // ── client_secret_post ──────────────────────────────────────────────
        if (hasFormSecret)
        {
            var client = await _clientStore.FindClientAsync(formClientId, ct);
            return client?.TokenEndpointAuthMethod == "client_secret_post" &&
                   client.ClientSecret is not null &&
                   ConstantTimeEquals(form["client_secret"].ToString(), client.ClientSecret)
                ? client : null;
        }

        var identified = await _clientStore.FindClientAsync(formClientId, ct);

        // ── none: public clients identify themselves only (RFC 6749 §2.1). Their tokens are
        //    protected by PKCE and, where used, DPoP binding instead of a credential.
        if (identified?.TokenEndpointAuthMethod == "none")
            return identified;

        // ── tls_client_auth / self_signed_tls_client_auth ───────────────────
        if (opts.MtlsEnabled)
        {
            var client = identified;
            if (client?.TokenEndpointAuthMethod is not ("tls_client_auth" or "self_signed_tls_client_auth"))
                return null;

            var cert = GetClientCertificate(context);
            if (cert is null) return null;

            return client.TokenEndpointAuthMethod == "tls_client_auth"
                ? ValidateTlsClientAuth(cert, client, opts) ? client : null
                : ValidateSelfSignedTlsClientAuth(cert, client) ? client : null;
        }

        return null;
    }

    // ── JWT assertion validation (RFC 7523 §3) ────────────────────────────────

    private async Task<Client?> AuthenticateJwtAssertionAsync(
        string assertion, string formClientId, ProviderOptions opts,
        string currentEndpointUrl, CancellationToken ct)
    {
        JsonWebToken unvalidated;
        try { unvalidated = _jwtHandler.ReadJsonWebToken(assertion); }
        catch { return null; }

        // iss and sub MUST both be the client_id (RFC 7523 §3, items 1–2).
        var clientId = unvalidated.Issuer;
        if (string.IsNullOrEmpty(clientId) || unvalidated.Subject != clientId)
            return null;
        if (!string.IsNullOrEmpty(formClientId) && formClientId != clientId)
            return null;

        var client = await _clientStore.FindClientAsync(clientId, ct);
        if (client is null) return null;

        var issuer = opts.Issuer.TrimEnd('/');
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = clientId,
            ValidAudiences = [issuer + opts.TokenEndpoint, issuer, currentEndpointUrl],
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = ClockSkew,
        };

        switch (client.TokenEndpointAuthMethod)
        {
            case "private_key_jwt":
            {
                if (client.JwksJson is null) return null;
                try { parameters.IssuerSigningKeys = new JsonWebKeySet(client.JwksJson).GetSigningKeys(); }
                catch { return null; }
                parameters.ValidAlgorithms = AsymmetricAlgorithms;
                break;
            }
            case "client_secret_jwt":
            {
                if (client.ClientSecret is null ||
                    !HmacMinKeyBytes.TryGetValue(unvalidated.Alg ?? string.Empty, out var minBytes))
                    return null;
                // RFC 7518 §3.2: the raw secret is the key and must be at least as long as the hash.
                var keyBytes = System.Text.Encoding.UTF8.GetBytes(client.ClientSecret);
                if (keyBytes.Length < minBytes) return null;
                parameters.IssuerSigningKey = new SymmetricSecurityKey(keyBytes);
                parameters.ValidAlgorithms = [unvalidated.Alg!];
                break;
            }
            default:
                return null;
        }

        var result = await _jwtHandler.ValidateTokenAsync(assertion, parameters);
        if (!result.IsValid) return null;

        // Bound the assertion lifetime so a leaked assertion is only briefly useful.
        var validTo = new DateTimeOffset(result.SecurityToken.ValidTo, TimeSpan.Zero);
        if (validTo - DateTimeOffset.UtcNow > TimeSpan.FromSeconds(opts.ClientAssertionMaxLifetimeSeconds) + ClockSkew)
            return null;

        // jti MUST be present and single-use (RFC 7523 §3, item 7).
        var jti = unvalidated.Id;
        if (string.IsNullOrEmpty(jti) ||
            !await _replayCache.TryAddAsync($"client-assertion:{clientId}:{jti}", validTo + ClockSkew, ct))
            return null;

        return client;
    }

    // ── mTLS helpers (RFC 8705) ───────────────────────────────────────────────

    /// <summary>
    /// Returns the client certificate from the TLS connection, or from
    /// <see cref="ProviderOptions.MtlsClientCertificateHeader"/> when the request comes
    /// directly from one of <see cref="ProviderOptions.MtlsTrustedProxies"/>.
    /// </summary>
    public X509Certificate2? GetClientCertificate(HttpContext context)
    {
        var opts = _options.Value;
        if (opts.MtlsClientCertificateHeader is not null && IsTrustedProxy(context.Connection.RemoteIpAddress, opts))
        {
            var header = context.Request.Headers[opts.MtlsClientCertificateHeader].ToString();
            if (!string.IsNullOrEmpty(header))
            {
                try { return X509Certificate2.CreateFromPem(Uri.UnescapeDataString(header)); }
                catch { return null; }
            }
        }

        return context.Connection.ClientCertificate;
    }

    private static bool IsTrustedProxy(IPAddress? remote, ProviderOptions opts)
    {
        if (remote is null) return false;
        if (remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();

        foreach (var entry in opts.MtlsTrustedProxies)
        {
            if (entry.Contains('/'))
            {
                if (IPNetwork.TryParse(entry, out var network) && network.Contains(remote))
                    return true;
            }
            else if (IPAddress.TryParse(entry, out var ip) && ip.Equals(remote))
            {
                return true;
            }
        }
        return false;
    }

    private static bool ValidateTlsClientAuth(X509Certificate2 cert, Client client, ProviderOptions opts)
    {
        // PKI method: the certificate must chain to a trusted CA (RFC 8705 §2.1).
        if (!ChainIsTrusted(cert, opts)) return false;

        return (client.TlsClientAuthSubjectDn is not null && SubjectDnMatches(cert, client.TlsClientAuthSubjectDn))
            || (client.TlsClientAuthSanDns is not null &&
                SanValues(cert, 2).Any(v => string.Equals(v, client.TlsClientAuthSanDns, StringComparison.OrdinalIgnoreCase)))
            || (client.TlsClientAuthSanUri is not null &&
                SanValues(cert, 6).Any(v => string.Equals(v, client.TlsClientAuthSanUri, StringComparison.Ordinal)))
            || (client.TlsClientAuthSanIp is not null && HasSanIp(cert, client.TlsClientAuthSanIp));
    }

    private static bool ChainIsTrusted(X509Certificate2 cert, ProviderOptions opts)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = opts.MtlsRevocationMode;
        chain.ChainPolicy.VerificationTime = DateTime.Now;
        if (opts.MtlsCertificateAuthorities.Count > 0)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(opts.MtlsCertificateAuthorities.ToArray());
        }
        try { return chain.Build(cert); }
        catch (CryptographicException) { return false; }
    }

    /// <summary>
    /// Compares subject DNs attribute-by-attribute (RFC 4514 semantics): same attribute types
    /// in the same order, values compared case-insensitively with whitespace normalised.
    /// </summary>
    internal static bool SubjectDnMatches(X509Certificate2 cert, string expected)
    {
        try
        {
            var actual = Normalise(cert.SubjectName);
            var wanted = Normalise(new X500DistinguishedName(expected));
            return actual.SequenceEqual(wanted);
        }
        catch (CryptographicException)
        {
            return false;
        }

        static List<(string Oid, string Value)> Normalise(X500DistinguishedName dn) =>
            dn.EnumerateRelativeDistinguishedNames()
                .Select(rdn => (
                    rdn.GetSingleElementType().Value ?? string.Empty,
                    string.Join(' ', (rdn.GetSingleElementValue() ?? string.Empty)
                        .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToUpperInvariant()))
                .ToList();
    }

    private static bool ValidateSelfSignedTlsClientAuth(X509Certificate2 cert, Client client)
    {
        // No PKI: the certificate is trusted because its key is registered (RFC 8705 §2.2),
        // but an expired or not-yet-valid certificate is still refused.
        var now = DateTime.Now;
        if (now < cert.NotBefore || now > cert.NotAfter) return false;
        if (client.JwksJson is null) return false;
        try
        {
            return new JsonWebKeySet(client.JwksJson).Keys.Any(key => PublicKeyMatchesCert(key, cert));
        }
        catch
        {
            return false;
        }
    }

    private static bool PublicKeyMatchesCert(JsonWebKey key, X509Certificate2 cert)
    {
        try
        {
            if (key.Kty == "RSA")
            {
                using var certRsa = cert.GetRSAPublicKey();
                if (certRsa is null) return false;
                var p = certRsa.ExportParameters(false);
                return Base64UrlEncoder.DecodeBytes(key.N).SequenceEqual(p.Modulus!) &&
                       Base64UrlEncoder.DecodeBytes(key.E).SequenceEqual(p.Exponent!);
            }

            if (key.Kty == "EC")
            {
                using var certEc = cert.GetECDsaPublicKey();
                if (certEc is null) return false;
                var p = certEc.ExportParameters(false);
                return key.X == Base64UrlEncoder.Encode(p.Q.X!) && key.Y == Base64UrlEncoder.Encode(p.Q.Y!);
            }
        }
        catch { /* mismatch */ }
        return false;
    }

    /// <summary>
    /// Computes the SHA-256 thumbprint of a certificate DER encoding,
    /// base64url-encoded per RFC 8705 §3.
    /// </summary>
    internal static string ComputeCertThumbprint(X509Certificate2 cert) =>
        Base64UrlEncoder.Encode(cert.GetCertHash(HashAlgorithmName.SHA256));

    // ── SAN helpers ────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns every IA5String GeneralName with the given context tag from the SAN extension
    /// (2 = dNSName, 6 = uniformResourceIdentifier).
    /// </summary>
    internal static IEnumerable<string> SanValues(X509Certificate2 cert, int tag)
    {
        var ext = cert.Extensions["2.5.29.17"];
        if (ext is null) return [];

        var values = new List<string>();
        try
        {
            var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
            var wanted = new Asn1Tag(TagClass.ContextSpecific, tag);
            while (reader.HasData)
            {
                if (reader.PeekTag().HasSameClassAndValue(wanted))
                    values.Add(reader.ReadCharacterString(UniversalTagNumber.IA5String, wanted));
                else
                    reader.ReadEncodedValue();
            }
        }
        catch (AsnContentException)
        {
            return [];
        }
        return values;
    }

    private static bool HasSanIp(X509Certificate2 cert, string expected)
    {
        if (!IPAddress.TryParse(expected, out var wanted)) return false;
        return cert.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(san => san.EnumerateIPAddresses())
            .Any(ip => ip.Equals(wanted));
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
            // RFC 6749 §2.3.1: client_id and secret are form-urlencoded.
            return (FormDecode(decoded[..colon]), FormDecode(decoded[(colon + 1)..]));
        }
        catch
        {
            return (null, null);
        }

        static string FormDecode(string s) => Uri.UnescapeDataString(s.Replace('+', ' '));
    }

    private static bool ConstantTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(a),
            System.Text.Encoding.UTF8.GetBytes(b));
}
