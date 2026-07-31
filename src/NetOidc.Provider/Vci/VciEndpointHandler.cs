using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Vci;

/// <summary>
/// Handles the OID4VCI credential endpoint (<c>POST /connect/credential</c>)
/// and nonce endpoint (<c>POST /connect/nonce</c>).
/// </summary>
public sealed class VciEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly TokenFactory _tokenFactory;
    private readonly VciService _vciService;

    public VciEndpointHandler(
        IOptions<ProviderOptions> options,
        TokenFactory tokenFactory,
        VciService vciService)
    {
        _options = options;
        _tokenFactory = tokenFactory;
        _vciService = vciService;
    }

    private static IResult Error(OAuthError err, int status) => Results.Json(err, statusCode: status);

    /// <summary><c>POST /connect/nonce</c> — issues a fresh c_nonce.</summary>
    public IResult HandleNonce()
    {
        if (!_options.Value.VciEnabled)
            return Error(OAuthError.InvalidRequest("VCI is not enabled"), 400);

        var nonce = _vciService.IssueNonce();
        return Results.Json(new
        {
            c_nonce = nonce,
            c_nonce_expires_in = _vciService.NonceLifetimeSeconds,
        });
    }

    /// <summary><c>POST /connect/credential</c> — validates an access token + proof and issues a VC.</summary>
    public async Task<IResult> HandleCredentialAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.VciEnabled)
            return Error(OAuthError.InvalidRequest("VCI is not enabled"), 400);

        if (opts.IssueCredential is null)
            return Error(OAuthError.ServerError("Credential issuance is not configured"), 500);

        // Extract and validate Bearer access token (OID4VCI 1.0 §7.1)
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"NetOidc\"";
            return Error(OAuthError.InvalidToken(), 401);
        }

        var rawToken = authHeader["Bearer ".Length..].Trim();
        var principal = await _tokenFactory.ValidateAccessTokenAsync(rawToken, ct);
        if (principal is null)
        {
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"NetOidc\", error=\"invalid_token\"";
            return Error(OAuthError.InvalidToken(), 401);
        }

        var subject = principal.FindFirst("sub")?.Value ?? principal.FindFirst("client_id")?.Value;

        if (!context.Request.HasJsonContentType())
            return Error(OAuthError.InvalidRequest("Content-Type must be application/json"), 400);

        JsonDocument body;
        try { body = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: ct); }
        catch { return Error(OAuthError.InvalidRequest("Invalid JSON body"), 400); }

        using (body)
        {
            var configId = body.RootElement.TryGetProperty("credential_configuration_id", out var cid)
                ? cid.GetString() : null;

            if (string.IsNullOrEmpty(configId))
                return Error(OAuthError.InvalidRequest("credential_configuration_id is required"), 400);

            if (!opts.VciCredentialConfigurations.Any(c => c.Id == configId))
                return Error(OAuthError.InvalidRequest($"Unknown credential_configuration_id: {configId}"), 400);

            // Validate optional proof JWT
            if (body.RootElement.TryGetProperty("proof", out var proofEl))
            {
                var proofErr = ValidateProofJwt(proofEl, opts);
                if (proofErr is not null)
                    return proofErr;
            }

            string credential;
            try
            {
                credential = await opts.IssueCredential(subject ?? string.Empty, configId, ct);
            }
            catch (Exception ex)
            {
                return Error(OAuthError.ServerError(ex.Message), 500);
            }

            return Results.Json(new { credential });
        }
    }

    private IResult? ValidateProofJwt(JsonElement proofEl, ProviderOptions opts)
    {
        var proofType = proofEl.TryGetProperty("proof_type", out var pt) ? pt.GetString() : null;
        if (proofType != "jwt")
            return null; // Unknown type — tolerate; only jwt proof nonce-binding is enforced

        var proofJwt = proofEl.TryGetProperty("jwt", out var pj) ? pj.GetString() : null;
        if (string.IsNullOrEmpty(proofJwt))
            return Error(OAuthError.InvalidProof("proof.jwt is required when proof_type is jwt"), 400);

        try
        {
            var handler = new JsonWebTokenHandler();
            var token = handler.ReadJsonWebToken(proofJwt);

            if (!string.Equals(token.Typ, "openid4vci-proof+jwt", StringComparison.OrdinalIgnoreCase))
                return Error(OAuthError.InvalidProof("proof JWT typ must be openid4vci-proof+jwt"), 400);

            var credIssuer = string.IsNullOrEmpty(opts.VciCredentialIssuer)
                ? opts.Issuer.TrimEnd('/')
                : opts.VciCredentialIssuer.TrimEnd('/');

            if (!token.Audiences.Contains(credIssuer, StringComparer.OrdinalIgnoreCase))
                return Error(OAuthError.InvalidProof("proof JWT audience must equal the credential issuer"), 400);

            // Consume the c_nonce when present
            if (token.TryGetClaim("nonce", out var nonceClaim) && !string.IsNullOrEmpty(nonceClaim.Value))
            {
                if (!_vciService.ConsumeNonce(nonceClaim.Value))
                    return Error(OAuthError.InvalidNonce(), 400);
            }
        }
        catch
        {
            return Error(OAuthError.InvalidProof("proof JWT is malformed"), 400);
        }

        return null;
    }
}
