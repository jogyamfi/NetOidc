namespace NetOidc.Provider.Abstractions.Models;

/// <summary>
/// A pre-authorized code from a credential offer (OID4VCI 1.0 §4.1.1, §6.1), redeemed at the
/// token endpoint with the <c>urn:ietf:params:oauth:grant-type:pre-authorized_code</c> grant.
/// </summary>
public sealed class PreAuthorizedCode
{
    public required string Code { get; init; }

    /// <summary>The End-User the issuer already authenticated out of band.</summary>
    public required string Subject { get; init; }

    public required IReadOnlyList<string> CredentialConfigurationIds { get; init; }

    /// <summary>SHA-256 (base64url) of the transaction code, when one is required.</summary>
    public string? TxCodeHash { get; init; }

    public int FailedTxCodeAttempts { get; set; }

    public required DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>A credential offer served by reference at the credential offer endpoint (OID4VCI 1.0 §4.1.3).</summary>
public sealed class StoredCredentialOffer
{
    public required string OfferId { get; init; }

    /// <summary>The credential offer object as JSON.</summary>
    public required string OfferJson { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>A deferred issuance awaiting the issuer (OID4VCI 1.0 §9).</summary>
public sealed class DeferredCredentialTransaction
{
    public required string TransactionId { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string CredentialConfigurationId { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
    public IReadOnlyList<string> HolderPublicJwks { get; init; } = [];
    public required DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>Links a <c>notification_id</c> to the issuance it reports on (OID4VCI 1.0 §11).</summary>
public sealed class CredentialNotificationRecord
{
    public required string NotificationId { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string CredentialConfigurationId { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}
