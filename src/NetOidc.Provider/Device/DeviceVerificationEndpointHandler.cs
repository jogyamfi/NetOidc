using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;
using NetOidc.Provider.Http;

namespace NetOidc.Provider.Device;

/// <summary>
/// Handles the user-facing device verification endpoint (RFC 8628 §3.3).
/// <c>GET  /connect/device</c> — shows user_code entry (headless: returns interaction contract).
/// <c>POST /connect/device</c> — processes user_code + authenticated user's approval/denial.
///
/// This is a headless contract: on GET it returns a 200 JSON interaction prompt including an
/// antiforgery token; on POST it processes the decision, which must carry that token. The host
/// renders the actual HTML views. Fetch the prompt after the user has signed in: the token is
/// bound to the signed-in identity.
/// </summary>
internal sealed class DeviceVerificationEndpointHandler
{
    private readonly IOptions<ProviderOptions> _options;
    private readonly IAdapter<DeviceCode> _deviceCodeStore;
    private readonly IAntiforgery _antiforgery;
    private readonly RequestThrottle _throttle;
    private readonly Abstractions.Events.IProviderEventSink _events;
    private readonly Microsoft.Extensions.Logging.ILogger<DeviceVerificationEndpointHandler> _logger;

    public DeviceVerificationEndpointHandler(
        IOptions<ProviderOptions> options,
        IAdapter<DeviceCode> deviceCodeStore,
        IAntiforgery antiforgery,
        RequestThrottle throttle,
        Abstractions.Events.IProviderEventSink events,
        Microsoft.Extensions.Logging.ILogger<DeviceVerificationEndpointHandler> logger)
    {
        _events = events;
        _logger = logger;
        _options = options;
        _deviceCodeStore = deviceCodeStore;
        _antiforgery = antiforgery;
        _throttle = throttle;
    }

    /// <summary>GET — return the verification prompt contract.</summary>
    public Task<IResult> HandleGetAsync(HttpContext context, CancellationToken ct)
    {
        var opts = _options.Value;
        if (!opts.DeviceFlowEnabled)
            return Task.FromResult(Error(OAuthError.InvalidRequest("Device authorization is not enabled"), 400));

        var prefilledUserCode = context.Request.Query["user_code"].ToString();

        // Issues the antiforgery cookie and returns the matching request token the host
        // must post back with the decision.
        var csrf = _antiforgery.GetAndStoreTokens(context);

        return Task.FromResult<IResult>(Results.Json(new
        {
            interaction = "device_verification",
            user_code_required = true,
            prefilled_user_code = string.IsNullOrEmpty(prefilledUserCode) ? null : prefilledUserCode,
            login_required = !context.User.Identity?.IsAuthenticated ?? true,
            csrf = new
            {
                field_name = csrf.FormFieldName,
                header_name = csrf.HeaderName,
                token = csrf.RequestToken,
            },
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

        // A cross-site form must not be able to approve a device for the signed-in user.
        try { await _antiforgery.ValidateRequestAsync(context); }
        catch (AntiforgeryValidationException)
        {
            return Error(OAuthError.InvalidRequest("missing or invalid antiforgery token"), 400);
        }

        // RFC 8628 §5.1: user codes are short, so limit how many a user may try.
        if (_throttle.IsUserCodeEntryBlocked(subject))
            return RequestThrottle.TooManyRequests(context, opts.DeviceUserCodeFailureWindowSeconds);

        var form = await context.Request.ReadFormAsync(ct);
        var rawUserCode = form["user_code"].ToString().Replace("-", "").Trim().ToUpperInvariant();
        if (string.IsNullOrEmpty(rawUserCode))
            return Error(OAuthError.InvalidRequest("user_code is required"), 400);

        var denied = form["action"].ToString().Equals("deny", StringComparison.OrdinalIgnoreCase);

        var key = DeviceAuthorizationEndpointHandler.UserCodeKey(rawUserCode);
        var deviceCode = await _deviceCodeStore.FindAsync(key, ct);
        if (deviceCode is null || deviceCode.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _throttle.RecordUserCodeFailure(subject);
            return Error(OAuthError.InvalidGrant("device code not found or expired"), 400);
        }

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
            deviceCode.AuthTime = DateTimeOffset.UtcNow;
            deviceCode.Status = DeviceCodeStatus.Approved;
        }

        // Persist the updated state (overwrite both keys, same TTL remaining)
        var remaining = deviceCode.ExpiresAt - DateTimeOffset.UtcNow;
        if (remaining > TimeSpan.Zero)
        {
            await _deviceCodeStore.StoreAsync(deviceCode.DeviceCodeValue, deviceCode, remaining, ct);
            await _deviceCodeStore.StoreAsync(key, deviceCode, remaining, ct);
        }

        Diagnostics.Log.AuthorizationDecision(_logger, "device_code", deviceCode.ClientId, denied ? "denied" : "approved");
        await _events.AuthorizationDecisionAsync(new Abstractions.Events.AuthorizationDecisionEvent(
            deviceCode.ClientId, subject, "device_code", !denied, DateTimeOffset.UtcNow), ct);

        return Results.Json(new
        {
            status = denied ? "denied" : "approved",
            client_id = deviceCode.ClientId,
        });
    }

    private static IResult Error(OAuthError error, int status) =>
        Results.Json(error, statusCode: status);
}
