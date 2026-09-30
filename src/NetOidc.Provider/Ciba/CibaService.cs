using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;
using NetOidc.Provider.Logout;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Ciba;

/// <summary>
/// Lets the host resolve CIBA authentication requests once the End-User has authenticated
/// (or refused) out of band.
/// </summary>
public interface ICibaService
{
    /// <summary>Returns the pending request, or <c>null</c> when unknown or expired.</summary>
    Task<BackchannelAuthenticationRequest?> FindAsync(string authReqId, CancellationToken ct = default);

    /// <summary>
    /// Approves (<paramref name="approve"/> = true, with the End-User's local
    /// <paramref name="subject"/>) or denies the request. For <c>ping</c> clients the
    /// notification endpoint is called; for <c>push</c> clients the tokens are delivered there.
    /// Returns false when the request is unknown, expired or already resolved.
    /// </summary>
    Task<bool> CompleteAsync(
        string authReqId, bool approve, string? subject = null,
        IReadOnlyList<string>? grantedScopes = null, string? acr = null,
        CancellationToken ct = default);
}

/// <summary>Default <see cref="ICibaService"/> (OpenID CIBA Core 1.0 §10).</summary>
internal sealed class CibaService : ICibaService
{
    private const string AuthReqIdClaim = "urn:openid:params:jwt:claim:auth_req_id";

    private readonly IAdapter<BackchannelAuthenticationRequest> _requests;
    private readonly IClientStore _clientStore;
    private readonly TokenIssuanceService _issuer;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<ProviderOptions> _options;
    private readonly ILogger<CibaService> _logger;
    private readonly Abstractions.Events.IProviderEventSink _events;

    public CibaService(
        IAdapter<BackchannelAuthenticationRequest> requests,
        IClientStore clientStore,
        TokenIssuanceService issuer,
        IHttpClientFactory httpClientFactory,
        IOptions<ProviderOptions> options,
        ILogger<CibaService> logger,
        Abstractions.Events.IProviderEventSink events)
    {
        _events = events;
        _requests = requests;
        _clientStore = clientStore;
        _issuer = issuer;
        _httpClientFactory = httpClientFactory;
        _options = options;
        _logger = logger;
    }

    public async Task<BackchannelAuthenticationRequest?> FindAsync(string authReqId, CancellationToken ct = default)
    {
        var request = await _requests.FindAsync(authReqId, ct);
        return request is not null && request.ExpiresAt > DateTimeOffset.UtcNow ? request : null;
    }

    public async Task<bool> CompleteAsync(
        string authReqId, bool approve, string? subject = null,
        IReadOnlyList<string>? grantedScopes = null, string? acr = null,
        CancellationToken ct = default)
    {
        if (approve && string.IsNullOrEmpty(subject))
            throw new ArgumentException("An approved request needs the End-User's subject.", nameof(subject));

        var request = await FindAsync(authReqId, ct);
        if (request is null || request.Status != BackchannelAuthenticationStatus.Pending)
            return false;

        var client = await _clientStore.FindClientAsync(request.ClientId, ct);
        if (client is null)
            return false;

        request.Status = approve ? BackchannelAuthenticationStatus.Approved : BackchannelAuthenticationStatus.Denied;
        if (approve)
        {
            request.Subject = subject;
            // Consent can only narrow what was requested.
            request.GrantedScopes = grantedScopes?.Where(request.RequestedScopes.Contains).ToList()
                                    ?? request.RequestedScopes;
            request.AuthTime = DateTimeOffset.UtcNow;
            request.Acr = acr;
        }

        Diagnostics.Log.AuthorizationDecision(_logger, "ciba", client.ClientId, approve ? "approved" : "denied");
        await _events.AuthorizationDecisionAsync(new Abstractions.Events.AuthorizationDecisionEvent(
            client.ClientId, request.Subject, "ciba", approve, DateTimeOffset.UtcNow), ct);

        var remaining = request.ExpiresAt - DateTimeOffset.UtcNow;
        switch (request.DeliveryMode)
        {
            case "push":
                // The tokens (or the error) go to the client; nothing remains to be polled.
                await _requests.RemoveAsync(authReqId, ct);
                await PushAsync(client, request, ct);
                break;
            case "ping":
                await _requests.StoreAsync(authReqId, request, remaining, ct);
                await NotifyAsync(client, request.ClientNotificationToken!, new { auth_req_id = authReqId }, ct);
                break;
            default:
                await _requests.StoreAsync(authReqId, request, remaining, ct);
                break;
        }
        return true;
    }

    /// <summary>CIBA §10.3: deliver the token response (or an error) to the notification endpoint.</summary>
    private async Task PushAsync(Client client, BackchannelAuthenticationRequest request, CancellationToken ct)
    {
        if (request.Status == BackchannelAuthenticationStatus.Denied)
        {
            await NotifyAsync(client, request.ClientNotificationToken!, new
            {
                auth_req_id = request.AuthReqId,
                error = "access_denied",
                error_description = "the End-User denied the authentication request",
            }, ct);
            return;
        }

        // Push delivery has no proof-of-possession channel, so tokens cannot be sender-constrained.
        var tokenRequest = TokenEndpointHandler.CibaTokenRequest(client, request, jkt: null, x5t: null) with { IdToken = null };
        var issued = await _issuer.IssueAsync(tokenRequest, ct);

        var extra = new Dictionary<string, object> { [AuthReqIdClaim] = request.AuthReqId };
        if (issued.RefreshToken is not null)
            extra["rt_hash"] = TokenFactory.HalfHash(issued.RefreshToken,
                client.IdTokenSignedResponseAlg ?? _options.Value.DefaultSigningAlgorithm);
        var idToken = request.GrantedScopes.Contains("openid")
            ? await _issuer.CreateIdTokenAsync(client, request.Subject!, request.GrantedScopes,
                new IdTokenParameters(request.AuthTime ?? request.CreatedAt, Acr: request.Acr, ExtraClaims: extra),
                issued.AccessToken, ct)
            : null;

        var payload = new Dictionary<string, object>
        {
            ["auth_req_id"] = request.AuthReqId,
            ["access_token"] = issued.AccessToken,
            ["token_type"] = issued.TokenType,
            ["expires_in"] = issued.ExpiresIn,
        };
        if (issued.RefreshToken is not null) payload["refresh_token"] = issued.RefreshToken;
        if (idToken is not null) payload["id_token"] = idToken;

        await NotifyAsync(client, request.ClientNotificationToken!, payload, ct);
    }

    /// <summary>POSTs JSON to the client notification endpoint with the client's bearer token (CIBA §10.2).</summary>
    private async Task NotifyAsync(Client client, string notificationToken, object payload, CancellationToken ct)
    {
        if (client.CibaClientNotificationEndpoint is null)
        {
            _logger.LogWarning("CIBA client {ClientId} has no notification endpoint", client.ClientId);
            return;
        }

        try
        {
            // URLs registered through DCR are untrusted: no private destinations, no redirects.
            var untrusted = client.IsDynamic && !_options.Value.DcrAllowPrivateNetworkUris;
            var http = _httpClientFactory.CreateClient(untrusted
                ? BackChannelLogoutService.UntrustedHttpClientName
                : BackChannelLogoutService.TrustedHttpClientName);

            using var message = new HttpRequestMessage(HttpMethod.Post, client.CibaClientNotificationEndpoint)
            {
                Content = JsonContent.Create(payload),
            };
            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", notificationToken);
            using var response = await http.SendAsync(message, ct);
            if (!response.IsSuccessStatusCode)
                _logger.LogWarning("CIBA notification to client {ClientId} returned {StatusCode}",
                    client.ClientId, (int)response.StatusCode);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "CIBA notification to client {ClientId} failed", client.ClientId);
        }
    }
}
