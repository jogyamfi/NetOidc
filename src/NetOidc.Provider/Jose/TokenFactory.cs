using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
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
    public string CreateAccessToken(
        string tokenId, string? subject, string clientId, IReadOnlyList<string> scopes)
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

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            Audience = opts.Issuer,
            IssuedAt = now,
            Expires = now.AddSeconds(opts.AccessTokenLifetimeSeconds),
            SigningCredentials = _keyProvider.GetSigningCredentials(),
            TokenType = "at+JWT",
            Claims = claims,
        };
        return _handler.CreateToken(descriptor);
    }

    /// <summary>Issues an ID token per OIDC Core spec.</summary>
    public string CreateIdToken(
        string subject,
        string clientId,
        string? nonce,
        DateTimeOffset authTime,
        string? acr = null,
        IReadOnlyList<string>? amr = null,
        IReadOnlyDictionary<string, object>? additionalClaims = null)
    {
        var opts = _options.Value;
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["sub"] = subject,
            ["auth_time"] = authTime.ToUnixTimeSeconds(),
        };
        if (nonce is not null) claims["nonce"] = nonce;
        if (acr is not null) claims["acr"] = acr;
        if (amr is not null && amr.Count > 0) claims["amr"] = amr;
        if (additionalClaims is not null)
            foreach (var kv in additionalClaims)
                claims[kv.Key] = kv.Value;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            Audience = clientId,
            IssuedAt = now,
            Expires = now.AddSeconds(opts.IdTokenLifetimeSeconds),
            SigningCredentials = _keyProvider.GetSigningCredentials(),
            Claims = claims,
        };
        return _handler.CreateToken(descriptor);
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
