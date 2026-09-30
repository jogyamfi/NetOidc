using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace NetOidc.Conformance;

/// <summary>
/// Key material for one conformance-suite client, generated per run: the suite gets the
/// private JWK and TLS client certificate (in the plan configuration); the OP registers the
/// public half.
/// </summary>
internal sealed class ClientCredentials
{
    public required string ClientId { get; init; }
    public required RSA Key { get; init; }
    public required X509Certificate2 Certificate { get; init; }

    public string KeyId => ClientId + "-ps256";

    /// <summary>The public JWKS the OP verifies client assertions and request objects with.</summary>
    public string PublicJwksJson
    {
        get
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(Key.ExportParameters(false)));
            return JsonSerializer.Serialize(new
            {
                keys = new[] { new { kty = "RSA", use = "sig", alg = "PS256", kid = KeyId, n = jwk.N, e = jwk.E } },
            });
        }
    }

    /// <summary>The private JWKS the suite signs with.</summary>
    public JsonObject PrivateJwks()
    {
        var p = Key.ExportParameters(true);
        string B(byte[]? b) => Base64UrlEncoder.Encode(b!);
        return new JsonObject
        {
            ["keys"] = new JsonArray(new JsonObject
            {
                ["kty"] = "RSA", ["use"] = "sig", ["alg"] = "PS256", ["kid"] = KeyId,
                ["n"] = B(p.Modulus), ["e"] = B(p.Exponent), ["d"] = B(p.D), ["p"] = B(p.P), ["q"] = B(p.Q),
                ["dp"] = B(p.DP), ["dq"] = B(p.DQ), ["qi"] = B(p.InverseQ),
            }),
        };
    }

    /// <summary>The <c>mtls</c> block of a plan configuration (self-signed: the CA is the certificate).</summary>
    public JsonObject Mtls() => new()
    {
        ["cert"] = Certificate.ExportCertificatePem(),
        ["key"] = Key.ExportPkcs8PrivateKeyPem(),
        ["ca"] = Certificate.ExportCertificatePem(),
    };

    public static ClientCredentials Create(string clientId)
    {
        var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={clientId}, O=NetOidc conformance", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return new ClientCredentials { ClientId = clientId, Key = key, Certificate = certificate };
    }
}

/// <summary>Credentials for every client of the running profile, created on first use.</summary>
internal sealed class ClientCredentialStore
{
    private readonly Dictionary<string, ClientCredentials> _clients = new(StringComparer.Ordinal);

    public ClientCredentials this[string clientId] =>
        _clients.TryGetValue(clientId, out var c) ? c : _clients[clientId] = ClientCredentials.Create(clientId);
}
