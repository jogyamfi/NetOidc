namespace NetOidc.Provider.Vci;

/// <summary>Input to <see cref="Configuration.ProviderOptions.IssueCredential"/>.</summary>
/// <param name="Subject">The End-User the credential is about (access token <c>sub</c>).</param>
/// <param name="CredentialConfigurationId">The requested <c>credential_configuration_id</c>.</param>
/// <param name="ClientId">The wallet (client) that obtained the access token.</param>
/// <param name="Scopes">Scopes carried by the access token.</param>
/// <param name="HolderPublicJwks">
/// Public JWKs (JSON) proven by the wallet, one per verified proof. The credential MUST be
/// bound to these keys; empty only when the configuration declares no binding method.
/// </param>
public sealed record CredentialIssuanceRequest(
    string Subject,
    string CredentialConfigurationId,
    string ClientId,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> HolderPublicJwks);
