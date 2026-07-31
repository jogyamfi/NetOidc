using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Configuration;
using OidcSession = NetOidc.Provider.Abstractions.Models.Session;

namespace NetOidc.Provider.Session;

/// <summary>
/// Creates and manages OIDC sessions. A session tracks which clients have
/// received tokens for a given subject within one user-agent session.
/// Session cookies hold the <c>sid</c> value; the session record is stored
/// via <see cref="IAdapter{Session}"/>.
/// </summary>
public sealed class SessionService
{
    internal const string CookieName = "netoidc.sid";

    private readonly IOptions<ProviderOptions> _options;
    private readonly IAdapter<OidcSession> _sessionStore;

    public SessionService(IOptions<ProviderOptions> options, IAdapter<OidcSession> sessionStore)
    {
        _options = options;
        _sessionStore = sessionStore;
    }

    /// <summary>
    /// Returns the current session for the request, or creates a new one and
    /// sets the session cookie. No-op when <see cref="ProviderOptions.LogoutEnabled"/>
    /// is false.
    /// </summary>
    public async Task<OidcSession?> EnsureSessionAsync(
        HttpContext context, string subject, string clientId, CancellationToken ct)
    {
        if (!_options.Value.LogoutEnabled) return null;

        var existingId = context.Request.Cookies[CookieName];
        if (existingId is not null)
        {
            var existing = await _sessionStore.FindAsync(existingId, ct);
            if (existing is not null && existing.Subject == subject)
            {
                // Add clientId to session if not already present.
                if (!existing.ClientIds.Contains(clientId))
                {
                    var updated = new OidcSession
                    {
                        SessionId = existing.SessionId,
                        Subject = existing.Subject,
                        ClientIds = [.. existing.ClientIds, clientId],
                        CreatedAt = existing.CreatedAt,
                        ExpiresAt = existing.ExpiresAt,
                    };
                    await _sessionStore.StoreAsync(existing.SessionId, updated, ct: ct);
                    return updated;
                }
                return existing;
            }
        }

        var sessionId = GenerateId();
        var session = new OidcSession
        {
            SessionId = sessionId,
            Subject = subject,
            ClientIds = [clientId],
        };
        await _sessionStore.StoreAsync(sessionId, session, ct: ct);
        context.Response.Cookies.Append(CookieName, sessionId, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
        });
        return session;
    }

    public Task<OidcSession?> GetSessionAsync(string sessionId, CancellationToken ct) =>
        _sessionStore.FindAsync(sessionId, ct);

    public Task RemoveSessionAsync(string sessionId, CancellationToken ct) =>
        _sessionStore.RemoveAsync(sessionId, ct);

    private static string GenerateId() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
