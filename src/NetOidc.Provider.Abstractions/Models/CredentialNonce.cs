namespace NetOidc.Provider.Abstractions.Models;

/// <summary>
/// A single-use OID4VCI <c>c_nonce</c> (OID4VCI 1.0 §7). Stored through
/// <c>IAdapter&lt;CredentialNonce&gt;</c> so that nonces issued by one instance can be redeemed
/// at another; the adapter's atomic <c>ConsumeAsync</c> enforces single use.
/// </summary>
public sealed class CredentialNonce
{
    public required string Nonce { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}
