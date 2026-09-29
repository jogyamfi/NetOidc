using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Jose;

/// <summary>
/// Validates JWT-Secured Authorization Request (JAR, RFC 9101) request objects.
/// Supports signed (JWS) and signed-then-encrypted (JWE nested) request objects
/// using keys from the client's inline <see cref="Client.JwksJson"/>.
/// </summary>
public sealed class RequestObjectValidator
{
    private readonly JsonWebTokenHandler _handler = new();
    private readonly KeyRing _keys;
    private readonly ILogger<RequestObjectValidator> _logger;

    public RequestObjectValidator(KeyRing keys, ILogger<RequestObjectValidator> logger)
    {
        _logger = logger;
        _keys = keys;
    }

    /// <summary>
    /// Validates the <paramref name="requestJwt"/> and returns its claims on success.
    /// </summary>
    /// <returns>
    /// <c>(claims, null)</c> on success; <c>(null, errorDescription)</c> on failure.
    /// </returns>
    public async Task<(IReadOnlyDictionary<string, object>? Claims, string? Error)> ValidateAsync(
        string requestJwt, Client client, string issuer, CancellationToken ct = default)
    {
        // Detect if the outer token is a JWE (encrypted) by checking the number of dots
        var dots = CountDots(requestJwt);

        string signedJwt;
        if (dots == 4)
        {
            // JWE: decrypt with the provider's encryption keys only. The inner JWS is verified
            // below against the client's keys (validating the JWE here would also try, and fail,
            // to verify that signature without them).
            try
            {
                var jwe = new JsonWebToken(requestJwt);
                if (jwe.Alg is null || !KeyRing.SupportedEncryptionAlgorithms.Contains(jwe.Alg) ||
                    jwe.Enc is null || !KeyRing.SupportedContentDecryptionAlgorithms.Contains(jwe.Enc))
                    return (null, "request object encryption algorithm is not supported");
                signedJwt = _handler.DecryptToken(jwe, new TokenValidationParameters
                {
                    TokenDecryptionKeys = _keys.GetDecryptionKeys(),
                });
            }
            catch (Exception ex) when (ex is not OperationCanceledException)   // attacker-controlled input
            {
                _logger.LogInformation(ex, "Request object decryption failed for client {ClientId}", client.ClientId);
                return (null, "failed to decrypt request object");
            }

            if (CountDots(signedJwt) != 2)
                return (null, "an encrypted request object must contain a signed JWT");
        }
        else if (dots == 2)
        {
            signedJwt = requestJwt;
        }
        else
        {
            return (null, "request object is not a valid JWT");
        }

        // Check for alg=none before attempting signature validation
        var headerJwt = new JsonWebToken(signedJwt);
        if (string.Equals(headerJwt.Alg, "none", StringComparison.OrdinalIgnoreCase))
            return (null, "request object must be signed; alg=none is not allowed");

        if (string.IsNullOrEmpty(client.JwksJson))
            return (null, "client has no JWKS configured; cannot verify request object signature");

        JsonWebKeySet jwks;
        try { jwks = new JsonWebKeySet(client.JwksJson); }
        catch { return (null, "client JWKS is malformed"); }

        var signingKeys = jwks.GetSigningKeys();
        if (signingKeys.Count == 0)
            return (null, "client JWKS contains no usable signing keys");

        // Validate expected alg when the client specifies one
        if (client.RequestObjectSigningAlg is not null &&
            !string.Equals(headerJwt.Alg, client.RequestObjectSigningAlg, StringComparison.OrdinalIgnoreCase))
        {
            return (null, $"request object uses alg '{headerJwt.Alg}' but client requires '{client.RequestObjectSigningAlg}'");
        }

        var result = await _handler.ValidateTokenAsync(signedJwt, new TokenValidationParameters
        {
            ValidIssuer = client.ClientId,
            ValidAudience = issuer,
            IssuerSigningKeys = signingKeys,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        });

        if (!result.IsValid)
        {
            _logger.LogInformation(result.Exception, "Request object validation failed for client {ClientId}", client.ClientId);
            return (null, "request object signature, issuer, audience or lifetime is invalid");
        }

        return ((IReadOnlyDictionary<string, object>)result.Claims, null);
    }

    /// <summary>JWT envelope claims that are not authorization request parameters.</summary>
    private static readonly HashSet<string> EnvelopeClaims =
        new(StringComparer.Ordinal) { "iss", "aud", "exp", "iat", "nbf", "jti" };

    /// <summary>
    /// Converts validated request-object claims into authorization request parameters.
    /// String claims are used as-is; structured claims (<c>claims</c>,
    /// <c>authorization_details</c>) are kept as their JSON text.
    /// </summary>
    public static Dictionary<string, string> ToAuthorizationParameters(
        IReadOnlyDictionary<string, object> claims)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in claims)
        {
            if (value is null || EnvelopeClaims.Contains(name)) continue;
            result[name] = value switch
            {
                string s => s,
                System.Text.Json.JsonElement { ValueKind: System.Text.Json.JsonValueKind.String } e => e.GetString()!,
                System.Text.Json.JsonElement e => e.GetRawText(),
                bool b => b ? "true" : "false",
                IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
                _ => System.Text.Json.JsonSerializer.Serialize(value),
            };
        }
        return result;
    }

    private static int CountDots(string s)
    {
        var count = 0;
        foreach (var c in s)
            if (c == '.') count++;
        return count;
    }
}
