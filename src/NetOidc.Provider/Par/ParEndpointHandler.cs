using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Par;

/// <summary>
/// Handles the Pushed Authorization Request endpoint (RFC 9126).
/// <c>POST /connect/par</c> — authenticates the client, validates basic authorization
/// request parameters, stores them under a <c>request_uri</c>, and returns
/// <c>{ request_uri, expires_in }</c>.
/// </summary>
public sealed class ParEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly IAdapter<PushedAuthorizationRequest> _parStore;

    public ParEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        IAdapter<PushedAuthorizationRequest> parStore)
    {
        _options = options;
        _clientStore = clientStore;
        _parStore = parStore;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.PushedAuthorizationEnabled)
            return ParError(OAuthError.InvalidRequest("Pushed authorization is not enabled"), 400);

        if (!context.Request.HasFormContentType)
            return ParError(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var client = await ClientAuthenticator.AuthenticateAsync(
            context, form, _clientStore, opts, ct);
        if (client is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return ParError(OAuthError.InvalidClient(), 401);
        }

        // Validate required parameters
        var clientId = form["client_id"].ToString();
        if (!string.IsNullOrEmpty(clientId) && clientId != client.ClientId)
            return ParError(OAuthError.InvalidRequest("client_id mismatch"), 400);

        var responseType = form["response_type"].ToString();
        if (string.IsNullOrEmpty(responseType))
            return ParError(OAuthError.InvalidRequest("response_type is required"), 400);

        var redirectUri = form["redirect_uri"].ToString();
        if (!string.IsNullOrEmpty(redirectUri) && !client.RedirectUris.Contains(redirectUri))
            return ParError(OAuthError.InvalidRequest("redirect_uri not registered for this client"), 400);

        // Store all form parameters as JSON
        var paramsDict = form.Keys
            .Where(k => k != "client_secret")   // never persist credentials
            .ToDictionary(k => k, k => form[k].ToString());
        paramsDict["client_id"] = client.ClientId;   // normalise

        var token = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var requestUri = $"urn:ietf:params:oauth:request_uri:{token}";

        var par = new PushedAuthorizationRequest
        {
            RequestUri = requestUri,
            ClientId = client.ClientId,
            ParametersJson = JsonSerializer.Serialize(paramsDict),
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.PushedAuthorizationLifetimeSeconds),
        };

        await _parStore.StoreAsync(
            requestUri, par,
            TimeSpan.FromSeconds(opts.PushedAuthorizationLifetimeSeconds), ct);

        return Results.Json(
            new { request_uri = requestUri, expires_in = opts.PushedAuthorizationLifetimeSeconds },
            statusCode: 201);
    }

    private static IResult ParError(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
