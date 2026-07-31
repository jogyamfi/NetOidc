namespace NetOidc.Provider.Vci;

/// <summary>
/// A credential type the issuer supports, advertised in
/// <c>credential_configurations_supported</c> of the credential issuer metadata
/// (OID4VCI 1.0 §11.2.3).
/// </summary>
public sealed class CredentialConfiguration
{
    /// <summary>Unique key in the <c>credential_configurations_supported</c> map.</summary>
    public required string Id { get; init; }

    /// <summary>Credential format (e.g. <c>jwt_vc_json</c>, <c>vc+sd-jwt</c>, <c>mso_mdoc</c>).</summary>
    public required string Format { get; init; }

    /// <summary>OAuth 2.0 scope that authorizes requesting this credential.</summary>
    public string? Scope { get; init; }

    /// <summary>Signing algorithms the issuer uses for credentials of this type.</summary>
    public IReadOnlyList<string> CredentialSigningAlgValuesSupported { get; init; } = ["RS256"];

    /// <summary>Cryptographic binding methods supported (e.g. <c>jwk</c>, <c>did:jwk</c>).</summary>
    public IReadOnlyList<string> CryptographicBindingMethodsSupported { get; init; } = ["jwk"];

    /// <summary>
    /// Proof type → supported signing alg values.
    /// E.g. <c>jwt</c> → <c>["RS256", "ES256"]</c>.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> ProofTypesSupported { get; init; }
        = new Dictionary<string, IReadOnlyList<string>>
          {
              ["jwt"] = ["RS256", "ES256"]
          };

    /// <summary>Verifiable credential type claim (<c>vct</c>) for VC+SD-JWT credentials.</summary>
    public string? Vct { get; init; }
}
