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

        // Sliding lifetime: every authorization in the session extends it.
        var lifetime = TimeSpan.FromSeconds(_options.Value.SessionLifetimeSeconds);
        var expiresAt = DateTimeOffset.UtcNow + lifetime;

        var existingId = context.Request.Cookies[CookieName];
        if (existingId is not null)
        {
            var existing = await _sessionStore.FindAsync(existingId, ct);
            if (existing is not null && existing.Subject == subject)
            {
                var updated = new OidcSession
                {
                    SessionId = existing.SessionId,
                    Subject = existing.Subject,
                    ClientIds = existing.ClientIds.Contains(clientId)
                        ? existing.ClientIds
                        : [.. existing.ClientIds, clientId],
                    CreatedAt = existing.CreatedAt,
                    ExpiresAt = expiresAt,
                };
                await _sessionStore.StoreAsync(existing.SessionId, updated, lifetime, ct);
                return updated;
            }
        }

        var sessionId = GenerateId();
        var session = new OidcSession
        {
            SessionId = sessionId,
            Subject = subject,
            ClientIds = [clientId],
            ExpiresAt = expiresAt,
        };
        await _sessionStore.StoreAsync(sessionId, session, lifetime, ct);
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

    /// <summary>Returns the session identified by the request's session cookie, if any.</summary>
    public Task<OidcSession?> GetCurrentSessionAsync(HttpContext context, CancellationToken ct) =>
        context.Request.Cookies[CookieName] is { } id
            ? _sessionStore.FindAsync(id, ct)
            : Task.FromResult<OidcSession?>(null);

    public Task RemoveSessionAsync(string sessionId, CancellationToken ct) =>
        _sessionStore.RemoveAsync(sessionId, ct);

    private static string GenerateId() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
