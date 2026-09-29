using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Jose;

/// <summary>Creates and validates JWT access tokens and ID tokens.</summary>
public sealed class TokenFactory
{
    private readonly SigningKeyProvider _keyProvider;
    private readonly IOptions<ProviderOptions> _options;
    private readonly JsonWebTokenHandler _handler = new();

    public TokenFactory(SigningKeyProvider keyProvider, IOptions<ProviderOptions> options)
    {
        _keyProvider = keyProvider;
        _options = options;
    }

    /// <summary>Issues a JWT access token per RFC 9068 (typ: at+JWT).</summary>
    /// <param name="subject">Resource owner subject, or <c>null</c> for client_credentials grants.</param>
    /// <param name="cnfJwkThumbprint">DPoP JWK thumbprint for <c>cnf.jkt</c> (RFC 9449), or <c>null</c>.</param>
    /// <param name="cnfX5tS256">mTLS certificate thumbprint for <c>cnf.x5t#S256</c> (RFC 8705), or <c>null</c>.</param>
    /// <param name="resources">
    /// Resource indicators (RFC 8707) the token is for. They are added to <c>aud</c> alongside
    /// the issuer, which keeps the token usable at the provider's own UserInfo endpoint.
    /// </param>
    public string CreateAccessToken(
        string tokenId, string? subject, string clientId, IReadOnlyList<string> scopes,
        string? cnfJwkThumbprint = null, string? cnfX5tS256 = null,
        IReadOnlyList<string>? resources = null)
    {
        var opts = _options.Value;
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["jti"] = tokenId,
            ["scope"] = string.Join(" ", scopes),
        };
        if (subject is not null) claims["sub"] = subject;
        if (resources is { Count: > 0 })
            claims["aud"] = new[] { opts.Issuer }.Concat(resources).Distinct(StringComparer.Ordinal).ToArray();

        // cnf claim (RFC 7800): bind the token to a proof-of-possession key or certificate.
        if (cnfJwkThumbprint is not null)
            claims["cnf"] = new Dictionary<string, string> { ["jkt"] = cnfJwkThumbprint };
        else if (cnfX5tS256 is not null)
            claims["cnf"] = new Dictionary<string, string> { ["x5t#S256"] = cnfX5tS256 };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            Audience = claims.ContainsKey("aud") ? null : opts.Issuer,
            IssuedAt = now,
            Expires = now.AddSeconds(opts.AccessTokenLifetimeSeconds),
            SigningCredentials = _keyProvider.GetSigningCredentials(),
            TokenType = "at+JWT",
            Claims = claims,
        };
        return _handler.CreateToken(descriptor);
    }

    /// <summary>Issues an ID token per OIDC Core spec, with optional encryption for the client.</summary>
    /// <param name="accessToken">When set, its <c>at_hash</c> is included (OIDC Core §3.3.2.11).</param>
    /// <param name="code">When set, its <c>c_hash</c> is included (OIDC Core §3.3.2.11).</param>
    public string CreateIdToken(
        string subject,
        string clientId,
        string? nonce,
        DateTimeOffset authTime,
        string? acr = null,
        IReadOnlyList<string>? amr = null,
        IReadOnlyDictionary<string, object>? additionalClaims = null,
        string? sid = null,
        Client? client = null,
        string? accessToken = null,
        string? code = null)
    {
        var opts = _options.Value;
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>();
        // User claims first so protocol claims below always win.
        if (additionalClaims is not null)
            foreach (var kv in additionalClaims)
                claims[kv.Key] = kv.Value;
        claims["sub"] = subject;
        claims["auth_time"] = authTime.ToUnixTimeSeconds();
        if (nonce is not null) claims["nonce"] = nonce;
        if (acr is not null) claims["acr"] = acr;
        if (amr is not null && amr.Count > 0) claims["amr"] = amr;
        if (sid is not null) claims["sid"] = sid;
        if (accessToken is not null) claims["at_hash"] = HalfHash(accessToken);
        if (code is not null) claims["c_hash"] = HalfHash(code);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            Audience = clientId,
            IssuedAt = now,
            Expires = now.AddSeconds(opts.IdTokenLifetimeSeconds),
            SigningCredentials = _keyProvider.GetSigningCredentials(),
            Claims = claims,
        };

        // Encrypt the id_token if the client registered encryption preferences and has a JWKS.
        if (client?.IdTokenEncryptedResponseAlg is not null && client.JwksJson is not null)
        {
            var encCreds = ResolveClientEncryptingCredentials(
                client.JwksJson,
                client.IdTokenEncryptedResponseAlg,
                client.IdTokenEncryptedResponseEnc ?? SecurityAlgorithms.Aes256CbcHmacSha512);
            if (encCreds is not null)
                descriptor.EncryptingCredentials = encCreds;
        }

        return _handler.CreateToken(descriptor);
    }

    /// <summary>Creates a JARM JWT wrapping authorization response parameters.</summary>
    public string CreateJarmToken(string clientId, IDictionary<string, string> responseParams)
    {
        var opts = _options.Value;
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["iss"] = opts.Issuer.TrimEnd('/'),
            ["aud"] = clientId,
        };
        foreach (var kv in responseParams)
            claims[kv.Key] = kv.Value;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            Audience = clientId,
            IssuedAt = now,
            Expires = now.AddMinutes(10),
            SigningCredentials = _keyProvider.GetSigningCredentials(),
            Claims = claims,
        };
        return _handler.CreateToken(descriptor);
    }

    /// <summary>
    /// <c>at_hash</c> / <c>c_hash</c> value: base64url of the left half of the hash of the ASCII
    /// value, using the hash of the ID token's signing algorithm (RS256 → SHA-256).
    /// </summary>
    public static string HalfHash(string value)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(value));
        return Base64UrlEncoder.Encode(hash.AsSpan(0, hash.Length / 2).ToArray());
    }

    private static EncryptingCredentials? ResolveClientEncryptingCredentials(
        string jwksJson, string alg, string enc)
    {
        try
        {
            var jwks = new JsonWebKeySet(jwksJson);
            // Find an encryption key (use=enc or no use restriction)
            foreach (var key in jwks.Keys)
            {
                if (key.Use is not null && key.Use != "enc") continue;
                if (key.Alg is not null &&
                    !string.Equals(key.Alg, alg, StringComparison.OrdinalIgnoreCase)) continue;

                return new EncryptingCredentials(key, alg, enc);
            }
        }
        catch { /* Malformed JWKS — skip encryption */ }
        return null;
    }

    /// <summary>
    /// Issues a Back-Channel Logout token (OIDC Back-Channel Logout §2.4).
    /// </summary>
    public string CreateLogoutToken(
        string subject, string clientId, string jti, string? sid,
        int lifetimeSeconds)
    {
        var opts = _options.Value;
        var now = DateTime.UtcNow;
        // "events" claim must be { "http://schemas.openid.net/event/backchannel-logout": {} }
        var events = new Dictionary<string, object>
        {
            // An empty JSON object; anonymous types cannot be serialized into JWT claims.
            ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>(),
        };
        var claims = new Dictionary<string, object>
        {
            ["sub"] = subject,
            ["jti"] = jti,
            ["events"] = events,
        };
        if (sid is not null) claims["sid"] = sid;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            Audience = clientId,
            IssuedAt = now,
            Expires = now.AddSeconds(lifetimeSeconds),
            SigningCredentials = _keyProvider.GetSigningCredentials(),
            // OIDC Back-Channel Logout §2.4: explicit typing prevents cross-JWT confusion.
            TokenType = "logout+jwt",
            Claims = claims,
        };
        return _handler.CreateToken(descriptor);
    }

    /// <summary>
    /// Validates an ID token (as id_token_hint). Returns the <see cref="ClaimsPrincipal"/>
    /// on success, or <c>null</c> if validation fails (lifetime errors are tolerated).
    /// </summary>
    public async Task<ClaimsPrincipal?> ValidateIdTokenHintAsync(
        string token, CancellationToken ct = default)
    {
        var opts = _options.Value;
        var result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = opts.Issuer,
            IssuerSigningKey = _keyProvider.GetValidationKey(),
            ValidateAudience = false,   // audience is the client_id — we don't restrict here
            ValidateLifetime = false,   // hints may be expired
        });
        return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
    }

    /// <summary>
    /// Validates an ID token issued by this provider, including its lifetime. Unlike
    /// <see cref="ValidateIdTokenHintAsync"/>, expired tokens are rejected, so this is the
    /// method to use whenever the ID token grants something (e.g. token exchange).
    /// </summary>
    public async Task<ClaimsPrincipal?> ValidateIdTokenAsync(
        string token, CancellationToken ct = default)
    {
        var opts = _options.Value;
        var result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = opts.Issuer,
            IssuerSigningKey = _keyProvider.GetValidationKey(),
            ValidateAudience = false,   // the caller compares aud/azp with its policy
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(5),
        });
        return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
    }

    /// <summary>
    /// Validates a JWT access token. Returns the <see cref="ClaimsPrincipal"/> on success,
    /// or <c>null</c> if validation fails.
    /// </summary>
    public async Task<ClaimsPrincipal?> ValidateAccessTokenAsync(
        string token, CancellationToken ct = default)
    {
        var opts = _options.Value;
        var result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = opts.Issuer,
            ValidAudience = opts.Issuer,
            IssuerSigningKey = _keyProvider.GetValidationKey(),
            ValidateLifetime = true,
            ValidTypes = ["at+JWT"],
            ClockSkew = TimeSpan.FromSeconds(5),
        });
        return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
    }
}
