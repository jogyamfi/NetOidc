using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Jose;

/// <summary>
/// Validates JWT-Secured Authorization Request (JAR, RFC 9101) request objects.
/// Supports signed (JWS) and signed-then-encrypted (JWE nested) request objects
/// using keys from the client's inline <see cref="Client.JwksJson"/>.
/// </summary>
internal sealed class RequestObjectValidator
{
    /// <summary>FAPI 1.0 Advanced §8.6 / FAPI 2.0 §5.4.1: the only permitted signing algorithms.</summary>
    internal static readonly string[] FapiSigningAlgorithms = ["PS256", "ES256"];

    /// <summary>FAPI 1.0 Advanced §5.2.2 items 13 and 17 (also FAPI 2.0 Message Signing, FAPI-CIBA).</summary>
    private static readonly TimeSpan FapiMaxRequestObjectAge = TimeSpan.FromMinutes(60);

    private readonly JsonWebTokenHandler _handler = new();
    private readonly KeyRing _keys;
    private readonly IOptions<ProviderOptions> _options;
    private readonly ClientJwksProvider _clientJwks;
    private readonly Http.SafeHttpFetcher _fetcher;
    private readonly ILogger<RequestObjectValidator> _logger;

    public RequestObjectValidator(KeyRing keys, IOptions<ProviderOptions> options, ClientJwksProvider clientJwks,
        Http.SafeHttpFetcher fetcher, ILogger<RequestObjectValidator> logger)
    {
        _logger = logger;
        _keys = keys;
        _options = options;
        _clientJwks = clientJwks;
        _fetcher = fetcher;
    }

    /// <summary>
    /// Fetches the request object a <c>request_uri</c> points at (RFC 9101 §5.2, OIDC Core §6.2).
    /// Only URIs the client pre-registered in <c>request_uris</c> are fetched (compared without
    /// the fragment), https only, through the SSRF-safe client and within
    /// <see cref="ProviderOptions.RequestUriMaxBytes"/>.
    /// </summary>
    /// <returns>The JWT, or an error description suitable for <c>invalid_request_uri</c>.</returns>
    public async Task<(string? Jwt, string? Error)> FetchAsync(string requestUri, Client client, CancellationToken ct)
    {
        static string WithoutFragment(string uri) => uri.Split('#', 2)[0];
        var target = WithoutFragment(requestUri);
        if (!client.RequestUris.Any(registered => string.Equals(WithoutFragment(registered), target, StringComparison.Ordinal)))
            return (null, "request_uri is not registered for this client");

        var opts = _options.Value;
        var document = await _fetcher.GetAsync(target, opts.RequestUriMaxBytes, "application/oauth-authz-req+jwt", ct,
            opts.DcrAllowPrivateNetworkUris);
        if (document is null)
            return (null, "request_uri could not be retrieved");
        return (document.Content.Trim(), null);
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
        JsonWebToken headerJwt;
        try { headerJwt = new JsonWebToken(signedJwt); }
        catch (ArgumentException) { return (null, "request object is not a valid JWT"); }   // attacker-controlled input
        if (string.Equals(headerJwt.Alg, "none", StringComparison.OrdinalIgnoreCase))
            return (null, "request object must be signed; alg=none is not allowed");

        var fapi = _options.Value.FapiProfile != FapiProfile.None;
        if (fapi && !FapiSigningAlgorithms.Contains(headerJwt.Alg))
            return (null, $"request objects must be signed with {string.Join(" or ", FapiSigningAlgorithms)}");

        var clientJwks = _clientJwks.Current(client);
        if (string.IsNullOrEmpty(clientJwks))
            return (null, "client has no JWKS configured; cannot verify request object signature");

        JsonWebKeySet jwks;
        try { jwks = new JsonWebKeySet(clientJwks); }
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

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = client.ClientId,
            ValidAudience = issuer,
            IssuerSigningKeys = signingKeys,
            ValidateLifetime = true,
            // OIDC Core §6.1 does not require exp in request objects (validated when present);
            // the FAPI profiles do, which FapiLifetimeError enforces.
            RequireExpirationTime = fapi,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
        var result = await _handler.ValidateTokenAsync(signedJwt, parameters);

        // The client may have rotated the keys at its jwks_uri (OIDC Core §10.1.1): re-fetch once.
        if (!result.IsValid && await _clientJwks.RefreshAsync(client, ct) is { } refreshed)
        {
            try
            {
                parameters.IssuerSigningKeys = new JsonWebKeySet(refreshed).GetSigningKeys();
                result = await _handler.ValidateTokenAsync(signedJwt, parameters);
            }
            catch (ArgumentException) { /* keep the original failure */ }
        }

        if (!result.IsValid)
        {
            _logger.LogInformation(result.Exception, "Request object validation failed for client {ClientId}", client.ClientId);
            return (null, "request object signature, issuer, audience or lifetime is invalid");
        }

        if (fapi && FapiLifetimeError(headerJwt) is { } lifetimeError)
            return (null, lifetimeError);

        return ((IReadOnlyDictionary<string, object>)result.Claims, null);
    }

    /// <summary>
    /// FAPI: <c>nbf</c> and <c>exp</c> are required, <c>nbf</c> is at most 60 minutes old and the
    /// request object lives at most 60 minutes.
    /// </summary>
    private static string? FapiLifetimeError(JsonWebToken token)
    {
        if (!token.TryGetPayloadValue<long>("nbf", out var nbf) || !token.TryGetPayloadValue<long>("exp", out var exp))
            return "request object must contain nbf and exp";
        var notBefore = DateTimeOffset.FromUnixTimeSeconds(nbf);
        if (DateTimeOffset.UtcNow - notBefore > FapiMaxRequestObjectAge)
            return "request object nbf is more than 60 minutes in the past";
        if (DateTimeOffset.FromUnixTimeSeconds(exp) - notBefore > FapiMaxRequestObjectAge)
            return "request object lifetime (exp - nbf) exceeds 60 minutes";
        return null;
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
