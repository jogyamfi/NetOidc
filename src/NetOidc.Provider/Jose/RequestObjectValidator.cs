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
    private readonly EncryptionKeyProvider _encryptionKeyProvider;

    public RequestObjectValidator(EncryptionKeyProvider encryptionKeyProvider)
    {
        _encryptionKeyProvider = encryptionKeyProvider;
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
            // JWE — decrypt first using OP's encryption key
            var decryptResult = await _handler.ValidateTokenAsync(requestJwt,
                new TokenValidationParameters
                {
                    ValidateLifetime = false,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateSignatureLast = false,
                    TokenDecryptionKey = _encryptionKeyProvider.GetDecryptionKey(),
                    // Do not validate signature — inner JWS will be validated below
                    RequireSignedTokens = false,
                });

            if (!decryptResult.IsValid)
                return (null, "failed to decrypt request object: " + (decryptResult.Exception?.Message ?? "unknown"));

            // Extract the inner JWS from the decrypted payload
            var innerToken = decryptResult.SecurityToken as JsonWebToken;
            if (innerToken is null)
                return (null, "decrypted request object is not a valid JWT");

            signedJwt = innerToken.InnerToken?.EncodedToken ?? requestJwt;
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
            return (null, result.Exception?.Message ?? "request object signature validation failed");

        return ((IReadOnlyDictionary<string, object>)result.Claims, null);
    }

    private static int CountDots(string s)
    {
        var count = 0;
        foreach (var c in s)
            if (c == '.') count++;
        return count;
    }
}
