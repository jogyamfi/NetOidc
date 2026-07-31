using Microsoft.Extensions.Options;

namespace NetOidc.Provider.Configuration;

/// <summary>
/// Validates <see cref="ProviderOptions"/> against the selected <see cref="FapiProfile"/>
/// at startup. Registered as <see cref="IValidateOptions{TOptions}"/> and only runs when
/// <see cref="ProviderOptions.FapiProfileValidationEnabled"/> is <c>true</c>.
/// </summary>
public sealed class FapiProfileValidator : IValidateOptions<ProviderOptions>
{
    private static readonly string[] Fapi1AllowedAuthMethods =
        ["private_key_jwt", "client_secret_jwt", "tls_client_auth", "none"];

    private static readonly string[] Fapi2AllowedAuthMethods =
        ["private_key_jwt", "tls_client_auth"];

    public ValidateOptionsResult Validate(string? name, ProviderOptions opts)
    {
        if (!opts.FapiProfileValidationEnabled || opts.FapiProfile == FapiProfile.None)
            return ValidateOptionsResult.Skip;

        var errors = new List<string>();

        switch (opts.FapiProfile)
        {
            case FapiProfile.Fapi1Advanced:
                ValidateFapi1(opts, errors);
                break;

            case FapiProfile.Fapi2Security:
                ValidateFapi2Security(opts, errors);
                break;

            case FapiProfile.Fapi2MessageSigning:
                ValidateFapi2Security(opts, errors);
                ValidateFapi2MessageSigning(opts, errors);
                break;

            case FapiProfile.FapiCiba:
                ValidateFapi2Security(opts, errors);
                ValidateFapiCiba(opts, errors);
                break;
        }

        return errors.Count > 0
            ? ValidateOptionsResult.Fail(errors)
            : ValidateOptionsResult.Success;
    }

    // ── FAPI 1.0 Advanced (OpenID FAPI 1.0 §5.2.2) ───────────────────────────

    private static void ValidateFapi1(ProviderOptions opts, List<string> errors)
    {
        foreach (var client in opts.StaticClients)
        {
            if (!Array.Exists(Fapi1AllowedAuthMethods, m => m == client.TokenEndpointAuthMethod))
                errors.Add(
                    $"[FAPI 1.0 §5.2.2] client '{client.ClientId}' uses auth method " +
                    $"'{client.TokenEndpointAuthMethod}' which is not allowed " +
                    "(must be private_key_jwt, client_secret_jwt, tls_client_auth, or none)");
        }
    }

    // ── FAPI 2.0 Security Profile (FAPI 2.0 §5.3.1) ──────────────────────────

    private static void ValidateFapi2Security(ProviderOptions opts, List<string> errors)
    {
        // Sender-constrained tokens are mandatory.
        if (!opts.DPoPEnabled && !opts.MtlsEnabled)
            errors.Add(
                "[FAPI 2.0 §5.3.1] sender-constrained access tokens are required; " +
                "enable DPoP (DPoPEnabled) or mTLS (MtlsEnabled)");

        // Authorization code lifetime must be ≤ 60 s.
        if (opts.AuthorizationCodeLifetimeSeconds > 60)
            errors.Add(
                $"[FAPI 2.0 §5.3.1] AuthorizationCodeLifetimeSeconds ({opts.AuthorizationCodeLifetimeSeconds}) " +
                "must be ≤ 60");

        // PAR is mandatory.
        if (!opts.RequirePushedAuthorization)
            errors.Add(
                "[FAPI 2.0 §5.3.1] RequirePushedAuthorization must be true");

        if (!opts.PushedAuthorizationEnabled)
            errors.Add(
                "[FAPI 2.0 §5.3.1] PushedAuthorizationEnabled must be true");

        // PAR request_uri lifetime must be ≤ 600 s.
        if (opts.PushedAuthorizationLifetimeSeconds > 600)
            errors.Add(
                $"[FAPI 2.0 §5.3.1] PushedAuthorizationLifetimeSeconds ({opts.PushedAuthorizationLifetimeSeconds}) " +
                "must be ≤ 600");

        // iss parameter in responses is mandatory.
        if (!opts.IssuerIdentificationEnabled)
            errors.Add(
                "[FAPI 2.0 §5.3.1] IssuerIdentificationEnabled must be true");

        // All registered clients must use private_key_jwt or tls_client_auth.
        foreach (var client in opts.StaticClients)
        {
            if (!Array.Exists(Fapi2AllowedAuthMethods, m => m == client.TokenEndpointAuthMethod))
                errors.Add(
                    $"[FAPI 2.0 §5.3.1] client '{client.ClientId}' uses auth method " +
                    $"'{client.TokenEndpointAuthMethod}' which is not allowed " +
                    "(must be private_key_jwt or tls_client_auth)");
        }
    }

    // ── FAPI 2.0 Message Signing ──────────────────────────────────────────────

    private static void ValidateFapi2MessageSigning(ProviderOptions opts, List<string> errors)
    {
        if (!opts.JarmEnabled)
            errors.Add(
                "[FAPI 2.0 Message Signing] JarmEnabled must be true for signed authorization responses");

        if (!opts.JarEnabled)
            errors.Add(
                "[FAPI 2.0 Message Signing] JarEnabled must be true for signed authorization requests");
    }

    // ── FAPI-CIBA ─────────────────────────────────────────────────────────────

    private static void ValidateFapiCiba(ProviderOptions opts, List<string> errors)
    {
        if (!opts.CibaEnabled)
            errors.Add(
                "[FAPI-CIBA] CibaEnabled must be true");
    }
}
