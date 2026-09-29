using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;

namespace NetOidc.Provider.Vci;

/// <summary>Transaction code the End-User must enter with a pre-authorized code (OID4VCI 1.0 §4.1.1).</summary>
/// <param name="InputMode"><c>numeric</c> or <c>text</c>.</param>
public sealed record TxCodeOptions(int Length = 6, string InputMode = "numeric", string? Description = null);

/// <summary>What a new credential offer grants.</summary>
public sealed class CredentialOfferRequest
{
    /// <summary>Offered credentials; each must be a configured <c>credential_configuration_id</c>.</summary>
    public required IReadOnlyList<string> CredentialConfigurationIds { get; init; }

    /// <summary>
    /// The End-User the issuer has already authenticated. When set, the offer carries a
    /// pre-authorized code for this subject.
    /// </summary>
    public string? PreAuthorizedSubject { get; init; }

    /// <summary>Require a transaction code, delivered to the End-User out of band, with the pre-authorized code.</summary>
    public TxCodeOptions? TxCode { get; init; }

    /// <summary>Also offer the authorization code grant.</summary>
    public bool IncludeAuthorizationCodeGrant { get; init; }

    /// <summary>Opaque value the wallet sends back as <c>issuer_state</c> in the authorization request.</summary>
    public string? IssuerState { get; init; }
}

/// <summary>A created credential offer.</summary>
/// <param name="OfferUri">The <c>openid-credential-offer://</c> URI to render as a QR code or link.</param>
/// <param name="CredentialOfferUri">Where the offer object is served by reference.</param>
/// <param name="TxCode">The transaction code to deliver to the End-User out of band, if one is required.</param>
public sealed record CreatedCredentialOffer(
    string OfferUri,
    string CredentialOfferUri,
    string OfferJson,
    string? PreAuthorizedCode,
    string? TxCode);

/// <summary>
/// Creates credential offers (OID4VCI 1.0 §4) and redeems their pre-authorized codes (§6.1).
/// Hosts call <see cref="CreateAsync"/> after authenticating the End-User in their own UI.
/// </summary>
public sealed class CredentialOfferService
{
    public const string PreAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    /// <summary>Client id recorded for tokens issued through anonymous pre-authorized access.</summary>
    public const string AnonymousClientId = "urn:netoidc:vci:anonymous";

    private const string TextAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    private readonly IOptions<ProviderOptions> _options;
    private readonly IAdapter<PreAuthorizedCode> _codes;
    private readonly IAdapter<StoredCredentialOffer> _offers;

    public CredentialOfferService(
        IOptions<ProviderOptions> options, IAdapter<PreAuthorizedCode> codes, IAdapter<StoredCredentialOffer> offers)
    {
        _options = options;
        _codes = codes;
        _offers = offers;
    }

    public async Task<CreatedCredentialOffer> CreateAsync(CredentialOfferRequest request, CancellationToken ct = default)
    {
        var opts = _options.Value;
        if (!opts.VciEnabled)
            throw new InvalidOperationException("VCI is not enabled.");
        if (request.CredentialConfigurationIds.Count == 0)
            throw new ArgumentException("At least one credential configuration is required.", nameof(request));
        foreach (var id in request.CredentialConfigurationIds)
            if (opts.VciCredentialConfigurations.All(c => c.Id != id))
                throw new ArgumentException($"Unknown credential configuration '{id}'.", nameof(request));
        if (request.PreAuthorizedSubject is null && !request.IncludeAuthorizationCodeGrant)
            throw new ArgumentException("An offer needs a pre-authorized subject or the authorization code grant.", nameof(request));
        if (request.TxCode is { } tx && (tx.Length is < 4 or > 32 || tx.InputMode is not ("numeric" or "text")))
            throw new ArgumentException("TxCode needs a length of 4-32 and input mode numeric or text.", nameof(request));

        var lifetime = TimeSpan.FromSeconds(opts.VciPreAuthorizedCodeLifetimeSeconds);
        var expiresAt = DateTimeOffset.UtcNow + lifetime;
        var grants = new JsonObject();

        if (request.IncludeAuthorizationCodeGrant)
        {
            var grant = new JsonObject();
            if (request.IssuerState is not null) grant["issuer_state"] = request.IssuerState;
            grants["authorization_code"] = grant;
        }

        string? code = null, txCode = null;
        if (request.PreAuthorizedSubject is not null)
        {
            code = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
            var grant = new JsonObject { ["pre-authorized_code"] = code };
            if (request.TxCode is { } options)
            {
                txCode = options.InputMode == "numeric"
                    ? string.Concat(Enumerable.Range(0, options.Length).Select(_ => (char)('0' + RandomNumberGenerator.GetInt32(10))))
                    : RandomNumberGenerator.GetString(TextAlphabet, options.Length);
                var txObject = new JsonObject { ["length"] = options.Length, ["input_mode"] = options.InputMode };
                if (options.Description is not null) txObject["description"] = options.Description;
                grant["tx_code"] = txObject;
            }
            grants[PreAuthorizedCodeGrantType] = grant;

            await _codes.StoreAsync(code, new PreAuthorizedCode
            {
                Code = code,
                Subject = request.PreAuthorizedSubject,
                CredentialConfigurationIds = request.CredentialConfigurationIds.ToList(),
                TxCodeHash = txCode is null ? null : Hash(txCode),
                ExpiresAt = expiresAt,
            }, lifetime, ct);
        }

        var offer = new JsonObject
        {
            ["credential_issuer"] = VciService.CredentialIssuer(opts),
            ["credential_configuration_ids"] = new JsonArray([.. request.CredentialConfigurationIds.Select(i => (JsonNode?)i)]),
            ["grants"] = grants,
        };
        var offerJson = offer.ToJsonString();

        var offerId = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(24));
        await _offers.StoreAsync(offerId,
            new StoredCredentialOffer { OfferId = offerId, OfferJson = offerJson, ExpiresAt = expiresAt }, lifetime, ct);

        var offerUri = $"{VciService.CredentialIssuer(opts)}{opts.VciCredentialOfferEndpoint}/{offerId}";
        return new CreatedCredentialOffer(
            QueryHelpers.AddQueryString("openid-credential-offer://", "credential_offer_uri", offerUri),
            offerUri, offerJson, code, txCode);
    }

    /// <summary>Returns the offer object served at the credential offer endpoint.</summary>
    public async Task<string?> FindOfferAsync(string offerId, CancellationToken ct) =>
        await _offers.FindAsync(offerId, ct) is { } offer && offer.ExpiresAt > DateTimeOffset.UtcNow ? offer.OfferJson : null;

    /// <summary>
    /// Redeems a pre-authorized code. A wrong transaction code counts against
    /// <see cref="ProviderOptions.VciTxCodeMaxAttempts"/>; the code is revoked when they run out.
    /// </summary>
    public async Task<(PreAuthorizedCode? Code, OAuthError? Error)> RedeemAsync(string code, string? txCode, CancellationToken ct)
    {
        var stored = await _codes.FindAsync(code, ct);
        if (stored is null || stored.ExpiresAt <= DateTimeOffset.UtcNow)
            return (null, OAuthError.InvalidGrant("pre-authorized_code is invalid or expired"));

        if (stored.TxCodeHash is null)
        {
            if (!string.IsNullOrEmpty(txCode))
                return (null, OAuthError.InvalidRequest("tx_code was not expected for this pre-authorized_code"));
        }
        else if (string.IsNullOrEmpty(txCode))
        {
            return (null, OAuthError.InvalidRequest("tx_code is required"));
        }
        else if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(txCode)), Encoding.ASCII.GetBytes(stored.TxCodeHash)))
        {
            stored.FailedTxCodeAttempts++;
            if (stored.FailedTxCodeAttempts >= _options.Value.VciTxCodeMaxAttempts)
                await _codes.RemoveAsync(code, ct);
            else
                await _codes.StoreAsync(code, stored, stored.ExpiresAt - DateTimeOffset.UtcNow, ct);
            return (null, OAuthError.InvalidGrant("tx_code is invalid"));
        }

        // Single use: concurrent redemptions race on the atomic consume.
        return await _codes.ConsumeAsync(code, ct) is { } consumed
            ? (consumed, null)
            : (null, OAuthError.InvalidGrant("pre-authorized_code is invalid or expired"));
    }

    private static string Hash(string value) => Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
