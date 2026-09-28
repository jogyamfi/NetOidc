using System.Text;
using Microsoft.Extensions.Options;

namespace NetOidc.Provider.Configuration;

/// <summary>
/// Validates security-relevant <see cref="ProviderOptions"/> at startup so that an unsafe
/// configuration fails fast instead of running.
/// </summary>
public sealed class ProviderOptionsValidator : IValidateOptions<ProviderOptions>
{
    /// <summary>Minimum pairwise salt length in bytes (256 bits).</summary>
    public const int MinPairwiseSaltBytes = 32;

    public ValidateOptionsResult Validate(string? name, ProviderOptions opts)
    {
        var errors = new List<string>();

        if (string.Equals(opts.SubjectType, "pairwise", StringComparison.OrdinalIgnoreCase))
        {
            // OIDC Core §8.1: pairwise identifiers must not be computable by third parties,
            // so the salt must be a secret — never derived from public values such as the issuer.
            if (string.IsNullOrEmpty(opts.PairwiseSalt) ||
                Encoding.UTF8.GetByteCount(opts.PairwiseSalt) < MinPairwiseSaltBytes)
                errors.Add($"PairwiseSalt must be a secret of at least {MinPairwiseSaltBytes} bytes " +
                           "when SubjectType is \"pairwise\".");

            foreach (var client in opts.StaticClients)
            {
                var hosts = client.RedirectUris
                    .Select(u => Uri.TryCreate(u, UriKind.Absolute, out var parsed) ? parsed.Host : u)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();
                if (hosts > 1 && client.SectorIdentifierUri is null)
                    errors.Add($"client '{client.ClientId}' has redirect URIs on {hosts} hosts; " +
                               "SectorIdentifierUri is required for pairwise subjects (OIDC Core §8.1).");
            }
        }

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
