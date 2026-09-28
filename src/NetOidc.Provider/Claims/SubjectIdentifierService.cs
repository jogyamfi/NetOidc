using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Claims;

/// <summary>
/// Computes the effective subject identifier for a given user+client pair.
/// Supports "public" (pass-through) and "pairwise" (OIDC Core §8.1) modes.
/// </summary>
public sealed class SubjectIdentifierService
{
    private readonly IOptions<ProviderOptions> _options;

    public SubjectIdentifierService(IOptions<ProviderOptions> options) => _options = options;

    /// <summary>
    /// Returns the subject to embed in tokens for the given raw <paramref name="subject"/> and
    /// <paramref name="client"/>. In pairwise mode this is HMAC-SHA256(salt, sector ‖ subject),
    /// where the sector is the client's <see cref="Client.SectorIdentifierUri"/> host, else its
    /// single redirect-URI host, else its client_id (clients with no redirect URIs).
    /// </summary>
    public string Compute(string subject, Client client)
    {
        var opts = _options.Value;
        if (!string.Equals(opts.SubjectType, "pairwise", StringComparison.OrdinalIgnoreCase))
            return subject;

        // Enforced at startup by ProviderOptionsValidator; never fall back to a public value.
        var salt = opts.PairwiseSalt
            ?? throw new InvalidOperationException("PairwiseSalt is required for pairwise subjects.");

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(salt));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(SectorOf(client) + "\x00" + subject));
        return Base64UrlEncoder.Encode(hash);
    }

    internal static string SectorOf(Client client)
    {
        if (client.SectorIdentifierUri is not null &&
            Uri.TryCreate(client.SectorIdentifierUri, UriKind.Absolute, out var sector))
            return sector.Host.ToLowerInvariant();

        var hosts = client.RedirectUris
            .Select(u => Uri.TryCreate(u, UriKind.Absolute, out var parsed) ? parsed.Host.ToLowerInvariant() : null)
            .Where(h => !string.IsNullOrEmpty(h))
            .Distinct()
            .ToList();

        return hosts.Count == 1 ? hosts[0]! : "client:" + client.ClientId;
    }
}
