using NetOidc.Provider.Abstractions.Models;

namespace NetOidc.Conformance;

/// <summary>The single End-User the conformance suite signs in as, with every standard claim.</summary>
internal static class ConformanceUser
{
    public const string Subject = "conformance-user";

    public static readonly Scope[] Scopes =
    [
        new() { Name = "openid" },
        new() { Name = "profile" },
        new() { Name = "email" },
        new() { Name = "address" },
        new() { Name = "phone" },
        new() { Name = "offline_access" },
    ];

    /// <summary>OIDC Core §5.1 standard claims; the provider releases only what was requested.</summary>
    public static IReadOnlyDictionary<string, object> Claims(string subject) => new Dictionary<string, object>
    {
        ["name"] = "Conformance User",
        ["given_name"] = "Conformance",
        ["family_name"] = "User",
        ["middle_name"] = "Q",
        ["nickname"] = "conf",
        ["preferred_username"] = subject,
        ["profile"] = "https://example.com/conformance-user",
        ["picture"] = "https://example.com/conformance-user.png",
        ["website"] = "https://example.com",
        ["gender"] = "unspecified",
        ["birthdate"] = "2000-01-01",
        ["zoneinfo"] = "Europe/London",
        ["locale"] = "en-GB",
        ["updated_at"] = 1_700_000_000L,
        ["email"] = "conformance-user@example.com",
        ["email_verified"] = true,
        ["phone_number"] = "+44 20 7946 0000",
        ["phone_number_verified"] = false,
        ["address"] = new Dictionary<string, object>
        {
            ["formatted"] = "1 Test Street\nLondon\nSW1A 1AA\nUnited Kingdom",
            ["street_address"] = "1 Test Street",
            ["locality"] = "London",
            ["postal_code"] = "SW1A 1AA",
            ["country"] = "GB",
        },
    };
}
