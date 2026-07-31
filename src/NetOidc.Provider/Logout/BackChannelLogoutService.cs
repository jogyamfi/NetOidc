using System.Security.Cryptography;
using NetOidc.Provider.Abstractions.Adapters;
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
    private readonly IClientStore _clientStore;
    private readonly TokenFactory _tokenFactory;
    private readonly IHttpClientFactory _httpClientFactory;

    public BackChannelLogoutService(
        IClientStore clientStore,
        TokenFactory tokenFactory,
        IHttpClientFactory httpClientFactory)
    {
        _clientStore = clientStore;
        _tokenFactory = tokenFactory;
        _httpClientFactory = httpClientFactory;
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
            var logoutToken = _tokenFactory.CreateLogoutToken(subject, clientId, jti, sid, lifetimeSeconds);

            var http = _httpClientFactory.CreateClient();
            var content = new FormUrlEncodedContent(
                [new KeyValuePair<string, string>("logout_token", logoutToken)]);
            using var response = await http.PostAsync(client.BackChannelLogoutUri, content, ct);
            // Best-effort: ignore errors per spec (§2.8).
        }
        catch
        {
            // Swallow — back-channel logout failures must not prevent the OP logout.
        }
    }

    private static string GenerateJti() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
