using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Token;

/// <summary>
/// Attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth,
/// method <c>attest_jwt_client_auth</c>). A trusted attester vouches for a client instance in
/// the <c>OAuth-Client-Attestation</c> header, binding it to a key; the instance proves
/// possession of that key in the <c>OAuth-Client-Attestation-PoP</c> header.
/// </summary>
internal sealed class ClientAttestationValidator
{
    public const string AuthMethod = "attest_jwt_client_auth";
    public const string AttestationHeader = "OAuth-Client-Attestation";
    public const string PopHeader = "OAuth-Client-Attestation-PoP";

    private const string AttestationType = "oauth-client-attestation+jwt";
    private const string PopType = "oauth-client-attestation-pop+jwt";
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    private static readonly string[] AsymmetricAlgorithms =
        ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];

    private readonly IOptions<ProviderOptions> _options;
    private readonly IReplayCache _replayCache;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    public ClientAttestationValidator(IOptions<ProviderOptions> options, IReplayCache replayCache)
    {
        _options = options;
        _replayCache = replayCache;
    }

    public static bool IsPresent(HttpContext context) =>
        context.Request.Headers.ContainsKey(AttestationHeader) || context.Request.Headers.ContainsKey(PopHeader);

    /// <summary>
    /// Verifies both headers and returns the attested <c>client_id</c>, or <c>null</c>.
    /// <paramref name="audiences"/> are the acceptable PoP audiences (the issuer, and the endpoint URL).
    /// </summary>
    public async Task<string?> ValidateAsync(HttpContext context, IReadOnlyCollection<string> audiences, CancellationToken ct)
    {
        var opts = _options.Value;
        if (opts.ClientAttestationTrustedAttesters.Count == 0)
            return null;

        var attestationHeader = context.Request.Headers[AttestationHeader];
        var popHeader = context.Request.Headers[PopHeader];
        if (attestationHeader.Count != 1 || popHeader.Count != 1 ||
            string.IsNullOrEmpty(attestationHeader[0]) || string.IsNullOrEmpty(popHeader[0]))
            return null;

        // ── Client attestation: signed by a trusted attester ─────────────────
        JsonWebToken attestation;
        try { attestation = _jwtHandler.ReadJsonWebToken(attestationHeader[0]); }
        catch (ArgumentException) { return null; }

        if (string.IsNullOrEmpty(attestation.Issuer) ||
            !opts.ClientAttestationTrustedAttesters.TryGetValue(attestation.Issuer, out var attesterJwks) ||
            Federation.EntityStatement.TryJwks(attesterJwks) is not { } attesterKeys)
            return null;

        var attestationResult = await _jwtHandler.ValidateTokenAsync(attestationHeader[0], new TokenValidationParameters
        {
            IssuerSigningKeys = attesterKeys.GetSigningKeys(),
            ValidIssuer = attestation.Issuer,
            ValidateAudience = false,
            RequireExpirationTime = true,
            ValidTypes = [AttestationType],
            ValidAlgorithms = AsymmetricAlgorithms,
            ClockSkew = ClockSkew,
        });
        if (!attestationResult.IsValid)
            return null;

        var clientId = attestation.Subject;
        if (string.IsNullOrEmpty(clientId) || InstanceKey(attestation) is not { } instanceKey)
            return null;

        // ── Proof of possession of the attested instance key ─────────────────
        var popResult = await _jwtHandler.ValidateTokenAsync(popHeader[0], new TokenValidationParameters
        {
            IssuerSigningKey = instanceKey,
            ValidIssuer = clientId,
            ValidAudiences = audiences,
            RequireExpirationTime = false,   // the PoP is bounded by iat below
            ValidTypes = [PopType],
            ValidAlgorithms = AsymmetricAlgorithms,
            ClockSkew = ClockSkew,
        });
        if (!popResult.IsValid)
            return null;

        var pop = (JsonWebToken)popResult.SecurityToken;
        var maxAge = TimeSpan.FromSeconds(opts.ClientAssertionMaxLifetimeSeconds);
        if (!pop.TryGetPayloadValue<long>("iat", out var iat) ||
            (DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(iat)).Duration() > maxAge + ClockSkew)
            return null;

        // jti is single use per client instance.
        if (string.IsNullOrEmpty(pop.Id) ||
            !await _replayCache.TryAddAsync($"client-attestation-pop:{clientId}:{pop.Id}",
                DateTimeOffset.FromUnixTimeSeconds(iat) + maxAge + ClockSkew, ct))
            return null;

        return clientId;
    }

    /// <summary>The public instance key from the attestation's <c>cnf.jwk</c>; never a private or symmetric key.</summary>
    private static JsonWebKey? InstanceKey(JsonWebToken attestation)
    {
        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(attestation.EncodedPayload));
            if (!payload.RootElement.TryGetProperty("cnf", out var cnf) || cnf.ValueKind != JsonValueKind.Object ||
                !cnf.TryGetProperty("jwk", out var jwk) || jwk.ValueKind != JsonValueKind.Object)
                return null;
            var key = new JsonWebKey(jwk.GetRawText());
            return string.IsNullOrEmpty(key.D) && string.IsNullOrEmpty(key.K) && key.Kty is "RSA" or "EC" or "OKP" ? key : null;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or FormatException)
        {
            return null;
        }
    }
}
