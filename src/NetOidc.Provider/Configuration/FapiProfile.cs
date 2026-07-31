namespace NetOidc.Provider.Configuration;

/// <summary>FAPI compliance profile applied to the provider.</summary>
public enum FapiProfile
{
    /// <summary>No FAPI profile; standard OIDC / OAuth 2.0 behaviour.</summary>
    None = 0,

    /// <summary>FAPI 1.0 Advanced Security Profile.</summary>
    Fapi1Advanced,

    /// <summary>FAPI 2.0 Security Profile (baseline sender-constrained profile).</summary>
    Fapi2Security,

    /// <summary>FAPI 2.0 Message Signing — FAPI 2.0 Security + JARM + JAR.</summary>
    Fapi2MessageSigning,

    /// <summary>FAPI-CIBA — FAPI 2.0 Security baseline with CIBA flow.</summary>
    FapiCiba,
}
