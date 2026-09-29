namespace NetOidc.Provider.Vci;

/// <summary>
/// Outcome of <see cref="Configuration.ProviderOptions.IssueCredential"/>: the issued
/// credentials (one per proven holder key), or a deferral (OID4VCI 1.0 §9).
/// </summary>
public sealed class CredentialIssuanceResult
{
    private CredentialIssuanceResult(IReadOnlyList<string> credentials, TimeSpan? retryAfter)
    {
        Credentials = credentials;
        RetryAfter = retryAfter;
    }

    /// <summary>The issued credentials; empty when deferred.</summary>
    public IReadOnlyList<string> Credentials { get; }

    /// <summary>When set, issuance is deferred and the wallet should retry after this interval.</summary>
    public TimeSpan? RetryAfter { get; }

    public bool IsDeferred => RetryAfter is not null;

    public static CredentialIssuanceResult Issued(params string[] credentials)
    {
        if (credentials.Length == 0 || credentials.Any(string.IsNullOrEmpty))
            throw new ArgumentException("At least one non-empty credential is required.", nameof(credentials));
        return new(credentials, null);
    }

    public static CredentialIssuanceResult Deferred(TimeSpan retryAfter) =>
        new([], retryAfter < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : retryAfter);

    public static implicit operator CredentialIssuanceResult(string credential) => Issued(credential);
}

/// <summary>Input to <see cref="Configuration.ProviderOptions.RetrieveDeferredCredential"/>.</summary>
/// <param name="TransactionId">The <c>transaction_id</c> the wallet presented.</param>
/// <param name="Request">The original, fully verified issuance request.</param>
public sealed record DeferredCredentialRequest(string TransactionId, CredentialIssuanceRequest Request);

/// <summary>A wallet's notification about issued credentials (OID4VCI 1.0 §11.1).</summary>
/// <param name="Event"><c>credential_accepted</c>, <c>credential_failure</c> or <c>credential_deleted</c>.</param>
public sealed record CredentialNotification(
    string NotificationId,
    string Event,
    string? EventDescription,
    string ClientId,
    string Subject,
    string CredentialConfigurationId);
