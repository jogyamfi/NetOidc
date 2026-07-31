using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Token;

namespace NetOidc.Provider.Device;

/// <summary>
/// Handles the Device Authorization endpoint (RFC 8628 §3.1).
/// <c>POST /connect/device_authorization</c> — authenticates the client, issues a
/// <c>device_code</c> / <c>user_code</c> pair, and returns the verification URI.
/// </summary>
public sealed class DeviceAuthorizationEndpointHandler
{
    private const string UserCodeChars = "BCDFGHJKLMNPQRSTVWXZ"; // consonants — easy to enter
    private const int UserCodeLength = 8;

    private readonly IOptions<ProviderOptions> _options;
    private readonly IClientStore _clientStore;
    private readonly IAdapter<DeviceCode> _deviceCodeStore;

    public DeviceAuthorizationEndpointHandler(
        IOptions<ProviderOptions> options,
        IClientStore clientStore,
        IAdapter<DeviceCode> deviceCodeStore)
    {
        _options = options;
        _clientStore = clientStore;
        _deviceCodeStore = deviceCodeStore;
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;

        if (!opts.DeviceFlowEnabled)
            return Error(OAuthError.InvalidRequest("Device authorization is not enabled"), 400);

        if (!context.Request.HasFormContentType)
            return Error(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        var form = await context.Request.ReadFormAsync(ct);

        var client = await ClientAuthenticator.AuthenticateAsync(context, form, _clientStore, opts, ct);
        if (client is null)
        {
            context.Response.Headers.WWWAuthenticate = "Basic realm=\"NetOidc\"";
            return Error(OAuthError.InvalidClient(), 401);
        }

        if (!client.AllowedGrantTypes.Contains("urn:ietf:params:oauth:grant-type:device_code"))
            return Error(OAuthError.UnauthorizedClient("device_code grant not allowed for this client"), 400);

        // Parse and validate scopes
        var scopeParam = form["scope"].ToString();
        var requestedScopes = string.IsNullOrEmpty(scopeParam)
            ? client.AllowedScopes.ToList()
            : scopeParam.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        foreach (var scope in requestedScopes)
        {
            if (!client.AllowedScopes.Contains(scope))
                return Error(OAuthError.InvalidScope($"scope '{scope}' is not allowed for this client"), 400);
        }

        var deviceCodeValue = GenerateSecureToken();
        var userCode = GenerateUserCode();
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(opts.DeviceCodeLifetimeSeconds);

        var deviceCode = new DeviceCode
        {
            DeviceCodeValue = deviceCodeValue,
            UserCode = userCode,
            ClientId = client.ClientId,
            RequestedScopes = requestedScopes,
            ExpiresAt = expiresAt,
        };

        await _deviceCodeStore.StoreAsync(
            deviceCodeValue, deviceCode,
            TimeSpan.FromSeconds(opts.DeviceCodeLifetimeSeconds), ct);

        // Also index by user_code for the verification endpoint lookup
        await _deviceCodeStore.StoreAsync(
            UserCodeKey(userCode), deviceCode,
            TimeSpan.FromSeconds(opts.DeviceCodeLifetimeSeconds), ct);

        var issuer = opts.Issuer.TrimEnd('/');
        var verificationUri = issuer + opts.DeviceVerificationUri;
        var verificationUriComplete = verificationUri + "?user_code=" + Uri.EscapeDataString(userCode);

        return Results.Json(new
        {
            device_code = deviceCodeValue,
            user_code = FormatUserCode(userCode),
            verification_uri = verificationUri,
            verification_uri_complete = verificationUriComplete,
            expires_in = opts.DeviceCodeLifetimeSeconds,
            interval = opts.DevicePollingIntervalSeconds,
        });
    }

    /// <summary>Key used in the adapter to look up a DeviceCode by its user_code.</summary>
    public static string UserCodeKey(string userCode) => "usercode:" + userCode.Replace("-", "").ToUpperInvariant();

    private static string GenerateSecureToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');

    private static string GenerateUserCode()
    {
        var chars = new char[UserCodeLength];
        var bytes = RandomNumberGenerator.GetBytes(UserCodeLength);
        for (var i = 0; i < UserCodeLength; i++)
            chars[i] = UserCodeChars[bytes[i] % UserCodeChars.Length];
        return new string(chars);
    }

    // Format as XXXX-XXXX for readability
    private static string FormatUserCode(string raw) =>
        raw.Length == UserCodeLength
            ? raw[..4] + "-" + raw[4..]
            : raw;

    private static IResult Error(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
