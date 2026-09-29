using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Claims;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Jose;
using OidcSession = NetOidc.Provider.Abstractions.Models.Session;

namespace NetOidc.Provider.Logout;

/// <summary>
/// Sends back-channel logout tokens to all RP clients that participated in a
/// session and have a <c>backchannel_logout_uri</c> registered
/// (OIDC Back-Channel Logout §2).
/// Failures are swallowed — logout proceeds regardless of RP availability.
/// </summary>
public sealed class BackChannelLogoutService
{
    internal const string TrustedHttpClientName = "NetOidc.BackChannelLogout";
    internal const string UntrustedHttpClientName = "NetOidc.BackChannelLogout.Untrusted";

    private readonly IClientStore _clientStore;
    private readonly TokenFactory _tokenFactory;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<ProviderOptions> _options;
    private readonly ILogger<BackChannelLogoutService> _logger;
    private readonly SubjectIdentifierService _subjects;

    public BackChannelLogoutService(
        IClientStore clientStore,
        TokenFactory tokenFactory,
        IHttpClientFactory httpClientFactory,
        IOptions<ProviderOptions> options,
        ILogger<BackChannelLogoutService> logger,
        SubjectIdentifierService subjects)
    {
        _subjects = subjects;
        _logger = logger;
        _clientStore = clientStore;
        _tokenFactory = tokenFactory;
        _httpClientFactory = httpClientFactory;
        _options = options;
    }

    /// <summary>
    /// Notifies each client in <paramref name="session"/> that the session has ended.
    /// Runs all notifications concurrently; individual failures are ignored.
    /// </summary>
    public async Task NotifyAsync(OidcSession session, int logoutTokenLifetimeSeconds, CancellationToken ct)
    {
        var tasks = session.ClientIds.Select(clientId =>
            NotifyClientAsync(clientId, session.Subject, session.SessionId, logoutTokenLifetimeSeconds, ct));
        await Task.WhenAll(tasks);
    }

    private async Task NotifyClientAsync(
        string clientId, string subject, string sessionId,
        int lifetimeSeconds, CancellationToken ct)
    {
        try
        {
            var client = await _clientStore.FindClientAsync(clientId, ct);
            if (client?.BackChannelLogoutUri is null) return;

            var jti = GenerateJti();
            var sid = client.BackChannelLogoutSessionRequired ? sessionId : null;
            // Each client receives the subject as it knows it (pairwise when configured).
            var logoutToken = _tokenFactory.CreateLogoutToken(
                _subjects.Compute(subject, client), clientId, jti, sid, lifetimeSeconds);

            // Operator-configured clients are trusted to target internal RPs; URLs supplied
            // through DCR are not.
            var untrusted = client.IsDynamic && !_options.Value.DcrAllowPrivateNetworkUris;
            var http = _httpClientFactory.CreateClient(
                untrusted ? UntrustedHttpClientName : TrustedHttpClientName);
            var content = new FormUrlEncodedContent(
                [new KeyValuePair<string, string>("logout_token", logoutToken)]);
            using var response = await http.PostAsync(client.BackChannelLogoutUri, content, ct);
            // Best-effort per spec (§2.8): a failing RP does not block the OP logout.
            if (!response.IsSuccessStatusCode)
                _logger.LogWarning("Back-channel logout to client {ClientId} returned {StatusCode}",
                    clientId, (int)response.StatusCode);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // Back-channel logout failures must not prevent the OP logout.
            _logger.LogWarning(ex, "Back-channel logout to client {ClientId} failed", clientId);
        }
    }

    private static string GenerateJti() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
