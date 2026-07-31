using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;

namespace NetOidc.Provider.Device;

/// <summary>
/// Handles the user-facing device verification endpoint (RFC 8628 §3.3).
/// <c>GET  /connect/device</c> — shows user_code entry (headless: returns interaction contract).
/// <c>POST /connect/device</c> — processes user_code + authenticated user's approval/denial.
///
/// This is a headless contract: on GET it returns a 200 JSON interaction prompt;
/// on POST it processes the decision. The sample host provides the actual HTML views.
/// </summary>
public sealed class DeviceVerificationEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IAdapter<DeviceCode> _deviceCodeStore;

    public DeviceVerificationEndpointHandler(
        IOptions<ProviderOptions> options,
        IAdapter<DeviceCode> deviceCodeStore)
    {
        _options = options;
        _deviceCodeStore = deviceCodeStore;
    }

    /// <summary>GET — return the verification prompt contract.</summary>
    public Task<IResult> HandleGetAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.DeviceFlowEnabled)
            return Task.FromResult(Error(OAuthError.InvalidRequest("Device authorization is not enabled"), 400));

        var prefilledUserCode = context.Request.Query["user_code"].ToString();

        return Task.FromResult<IResult>(Results.Json(new
        {
            interaction = "device_verification",
            user_code_required = true,
            prefilled_user_code = string.IsNullOrEmpty(prefilledUserCode) ? null : prefilledUserCode,
            login_required = !context.User.Identity?.IsAuthenticated ?? true,
        }));
    }

    /// <summary>POST — approve or deny the device based on the authenticated user's action.</summary>
    public async Task<IResult> HandlePostAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.DeviceFlowEnabled)
            return Error(OAuthError.InvalidRequest("Device authorization is not enabled"), 400);

        if (!context.Request.HasFormContentType)
            return Error(OAuthError.InvalidRequest("Content-Type must be application/x-www-form-urlencoded"), 400);

        // Require the user to be authenticated
        if (!(context.User.Identity?.IsAuthenticated ?? false))
            return Results.Redirect(opts.LoginPath + "?returnUrl=" +
                Uri.EscapeDataString(opts.DeviceVerificationUri));

        var subject = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? context.User.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(subject))
            return Error(OAuthError.InvalidRequest("Cannot determine authenticated user identity"), 400);

        var form = await context.Request.ReadFormAsync(ct);
        var rawUserCode = form["user_code"].ToString().Replace("-", "").Trim().ToUpperInvariant();
        if (string.IsNullOrEmpty(rawUserCode))
            return Error(OAuthError.InvalidRequest("user_code is required"), 400);

        var denied = form["action"].ToString().Equals("deny", StringComparison.OrdinalIgnoreCase);

        var key = DeviceAuthorizationEndpointHandler.UserCodeKey(rawUserCode);
        var deviceCode = await _deviceCodeStore.FindAsync(key, ct);
        if (deviceCode is null || deviceCode.ExpiresAt <= DateTimeOffset.UtcNow)
            return Error(OAuthError.InvalidGrant("device code not found or expired"), 400);

        if (deviceCode.Status != DeviceCodeStatus.Pending)
            return Error(OAuthError.InvalidGrant("device code has already been used"), 400);

        if (denied)
        {
            deviceCode.Status = DeviceCodeStatus.Denied;
        }
        else
        {
            deviceCode.Subject = subject;
            deviceCode.GrantedScopes = deviceCode.RequestedScopes;
            deviceCode.Status = DeviceCodeStatus.Approved;
        }

        // Persist the updated state (overwrite both keys, same TTL remaining)
        var remaining = deviceCode.ExpiresAt - DateTimeOffset.UtcNow;
        if (remaining > TimeSpan.Zero)
        {
            await _deviceCodeStore.StoreAsync(deviceCode.DeviceCodeValue, deviceCode, remaining, ct);
            await _deviceCodeStore.StoreAsync(key, deviceCode, remaining, ct);
        }

        return Results.Json(new
        {
            status = denied ? "denied" : "approved",
            client_id = deviceCode.ClientId,
        });
    }

    private static IResult Error(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
