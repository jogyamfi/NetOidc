using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Ciba;

/// <summary>
/// Handles the CIBA Backchannel Authentication endpoint (OpenID CIBA Core 1.0 §7.1).
/// <c>POST /connect/ciba</c> — authenticates the client, accepts a login_hint /
/// id_token_hint, stores a pending <see cref="BackchannelAuthenticationRequest"/>, and
/// returns <c>{ auth_req_id, expires_in, interval }</c>.
///
/// Only poll mode is implemented in Phase 6. Ping / push delivery modes are reserved
/// for a future phase.
/// </summary>
public sealed class CibaEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly IAdapter<BackchannelAuthenticationRequest> _cibaStore;

    public CibaEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        IAdapter<BackchannelAuthenticationRequest> cibaStore)
    {
        _options = options;
        _clientStore = clientStore;
        _cibaStore = cibaStore;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.CibaEnabled)
            return Error(OAuthError.InvalidRequest("CIBA is not enabled"), 400);

        if (!context.Request.HasFormContentType)
            return Error(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var client = await ClientAuthenticator.AuthenticateAsync(context, form, _clientStore, opts, ct);
        if (client is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return Error(OAuthError.InvalidClient(), 401);
        }

        if (!client.AllowedGrantTypes.Contains("urn:ietf:params:oauth:grant-type:ciba"))
            return Error(OAuthError.UnauthorizedClient("CIBA grant not allowed for this client"), 400);

        // CIBA Core §7.1: at least one hint is required
        var loginHint = form["login_hint"].ToString();
        var idTokenHint = form["id_token_hint"].ToString();
        var loginHintToken = form["login_hint_token"].ToString();

        if (string.IsNullOrEmpty(loginHint) &&
            string.IsNullOrEmpty(idTokenHint) &&
            string.IsNullOrEmpty(loginHintToken))
        {
            return Error(OAuthError.InvalidRequest(
                "At least one of login_hint, id_token_hint, or login_hint_token is required"), 400);
        }

        // Only one hint at a time
        var hintsProvided = new[] { loginHint, idTokenHint, loginHintToken }
            .Count(h => !string.IsNullOrEmpty(h));
        if (hintsProvided > 1)
            return Error(OAuthError.InvalidRequest("Only one of login_hint, id_token_hint, login_hint_token may be provided"), 400);

        // Parse and validate scopes
        var scopeParam = form["scope"].ToString();
        if (string.IsNullOrEmpty(scopeParam))
            return Error(OAuthError.InvalidRequest("scope is required"), 400);

        var requestedScopes = scopeParam.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        if (!requestedScopes.Contains("openid"))
            return Error(OAuthError.InvalidScope("openid scope is required for CIBA"), 400);

        foreach (var scope in requestedScopes)
        {
            if (!client.AllowedScopes.Contains(scope))
                return Error(OAuthError.InvalidScope($"scope '{scope}' is not allowed for this client"), 400);
        }

        var bindingMessage = form["binding_message"].ToString();
        var userCode = form["user_code"].ToString();

        var authReqId = GenerateSecureToken();
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.CibaAuthReqIdLifetimeSeconds);

        var authRequest = new BackchannelAuthenticationRequest
        {
            AuthReqId = authReqId,
            ClientId = client.ClientId,
            LoginHint = string.IsNullOrEmpty(loginHint) ? null : loginHint,
            IdTokenHint = string.IsNullOrEmpty(idTokenHint) ? null : idTokenHint,
            RequestedScopes = requestedScopes,
            BindingMessage = string.IsNullOrEmpty(bindingMessage) ? null : bindingMessage,
            ExpiresAt = expiresAt,
        };

        await _cibaStore.StoreAsync(
            authReqId, authRequest,
            TimeSpan.FromSeconds(opts.CibaAuthReqIdLifetimeSeconds), ct);

        // Trigger out-of-band authentication (fire-and-forget; hook is responsible for
        // calling back to approve/deny the request).
        if (opts.ProcessBackchannelAuthenticationRequest is not null)
            _ = opts.ProcessBackchannelAuthenticationRequest(authRequest, ct);

        return Results.Json(new
        {
            auth_req_id = authReqId,
            expires_in = opts.CibaAuthReqIdLifetimeSeconds,
            interval = opts.CibaPollingIntervalSeconds,
        });
    }

    private static string GenerateSecureToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

    private static IResult Error(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
