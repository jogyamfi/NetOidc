using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Provider.Token;

/// <summary>
/// Extracts and validates client credentials from either HTTP Basic auth or form body.
/// Enforces the <c>token_endpoint_auth_method</c> configured on the client.
/// </summary>
internal static class ClientAuthenticator
{
    public static async Task<Client?> AuthenticateAsync(
        HttpContext context, IFormCollection form, IClientStore clientStore, CancellationToken ct)
    {
        // Try HTTP Basic first
        var (basicId, basicSecret) = TryParseBasicAuth(context);
        if (basicId is not null)
        {
            var client = await clientStore.FindClientAsync(basicId, ct);
            if (client?.TokenEndpointAuthMethod == "client_secret_basic" &&
                client.ClientSecret is not null &&
                ConstantTimeEquals(basicSecret ?? string.Empty, client.ClientSecret))
                return client;
            return null;
        }

        // Fall back to form body
        var formId = form["client_id"].ToString();
        if (!string.IsNullOrEmpty(formId))
        {
            var client = await clientStore.FindClientAsync(formId, ct);
            var formSecret = form["client_secret"].ToString();
            if (client?.TokenEndpointAuthMethod == "client_secret_post" &&
                client.ClientSecret is not null &&
                ConstantTimeEquals(formSecret, client.ClientSecret))
                return client;
            return null;
        }

        return null;
    }

    private static (string? Id, string? Secret) TryParseBasicAuth(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return (null, null);

        try
        {
            var decoded = System.Text.Encoding.UTF8.GetString(
                Convert.FromBase64String(header["Basic ".Length..].Trim()));
            var colon = decoded.IndexOf(':');
            if (colon < 0) return (null, null);
            // RFC 6749 §2.3.1: client_id and secret are URL-encoded
            return (Uri.UnescapeDataString(decoded[..colon]),
                    Uri.UnescapeDataString(decoded[(colon + 1)..]));
        }
        catch
        {
            return (null, null);
        }
    }

    private static bool ConstantTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(a),
            System.Text.Encoding.UTF8.GetBytes(b));
}
