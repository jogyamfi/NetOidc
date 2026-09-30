using System.Text.Json.Nodes;

namespace NetOidc.Conformance;

/// <summary>
/// The suite's scripted-browser instructions for this host's pages (<c>browser</c> and
/// <c>override</c> in a plan configuration).
/// </summary>
internal static class SuiteBrowser
{
    private static JsonArray Command(params object[] parts) => new([.. parts.Select(p => p switch
    {
        int i => (JsonNode)JsonValue.Create(i),
        _ => JsonValue.Create(p.ToString()!),
    })]);

    private static JsonObject Task(string name, string match, bool optional, params JsonArray[] commands)
    {
        var task = new JsonObject { ["task"] = name, ["match"] = match };
        if (optional) task["optional"] = true;
        if (commands.Length > 0) task["commands"] = new JsonArray([.. commands]);
        return task;
    }

    private static JsonObject Login(ConformanceSettings s, bool screenshot) => Task("Login", s.Op("/account/login*"), true,
        screenshot
            ? [Command("wait", "xpath", "//*", 10, "Sign in", "update-image-placeholder-optional"), Command("click", "id", "login-submit")]
            : [Command("click", "id", "login-submit")]);

    private static JsonObject Consent(ConformanceSettings s, bool screenshot) => Task("Consent", s.Op("/account/consent*"), !screenshot,
        screenshot
            ? [Command("wait", "xpath", "//*", 10, "Allow", "update-image-placeholder"), Command("click", "id", "consent-submit")]
            : [Command("click", "id", "consent-submit")]);

    private static JsonObject VerifyCallback() =>
        Task("Verify Complete", "*/test/*/callback*", false, Command("wait", "id", "submission_complete", 10));

    private static JsonArray Authorize(ConformanceSettings s, bool loginScreenshot = false, bool consentScreenshot = false) =>
    [
        new JsonObject
        {
            ["match"] = s.Op("/connect/authorize*"),
            ["tasks"] = new JsonArray(Login(s, loginScreenshot), Consent(s, consentScreenshot), VerifyCallback()),
        },
    ];

    private static JsonObject EndSession(ConformanceSettings s) => new()
    {
        ["match"] = s.Op("/connect/end_session*"),
        ["tasks"] = new JsonArray(
            Task("Confirm logout", s.Op("/account/logout*"), true, Command("click", "id", "logout-submit")),
            Task("Verify Complete", "*/test/*/post*", false)),
    };

    /// <summary>Log in, consent when asked, and wait for the suite's callback; confirm logouts.</summary>
    public static JsonArray Default(ConformanceSettings s) => [.. Authorize(s).Select(n => n!.DeepClone()), EndSession(s)];

    /// <summary>
    /// The OP shows its error page at <paramref name="path"/>; the suite wants a screenshot of it.
    /// For logout tests the End-User first signs in as usual.
    /// </summary>
    private static JsonObject ErrorPage(ConformanceSettings s, string path, bool signInFirst = false)
    {
        var errorPage = new JsonObject
        {
            ["match"] = s.Op(path),
            ["tasks"] = new JsonArray(Task("Expect error page", s.Op(path), false,
                Command("wait", "xpath", "//*", 10, "NetOidc error", "update-image-placeholder"))),
        };
        return new JsonObject
        {
            ["browser"] = signInFirst
                ? new JsonArray([.. Authorize(s).Select(n => n!.DeepClone()), errorPage])
                : new JsonArray(errorPage),
        };
    }

    /// <summary>The logout ends on the OP's own page; the suite wants a screenshot of it.</summary>
    private static JsonObject LogoutPage(ConformanceSettings s, string expectedText) => new()
    {
        ["browser"] = new JsonArray(
            Authorize(s)[0]!.DeepClone(),
            new JsonObject
            {
                ["match"] = s.Op("/connect/end_session*"),
                ["tasks"] = new JsonArray(
                    Task("Confirm logout", s.Op("/account/logout*"), true, Command("click", "id", "logout-submit")),
                    Task("Expect page", s.Op("/connect/end_session*"), false,
                        Command("wait", "xpath", "//*", 10, expectedText, "update-image-placeholder"))),
            }),
    };

    /// <summary>Per-test browser instructions for the FAPI plans.</summary>
    public static JsonObject FapiOverrides(ConformanceSettings s)
    {
        // The authorization endpoint is visited twice with one request_uri: the first visit must
        // only reach the login page (match-limit 1), the second logs in as usual.
        JsonObject ReusedRequestUri() => new()
        {
            ["browser"] = new JsonArray(
            [
                new JsonObject
                {
                    ["match"] = s.Op("/connect/authorize*"),
                    ["match-limit"] = 1,
                    ["tasks"] = new JsonArray(Task("Reach login page", s.Op("/account/login*"), false,
                        Command("wait", "id", "login-submit", 10))),
                },
                .. Authorize(s).Select(n => n!.DeepClone()),
            ]),
        };
        // The End-User presses cancel on the login page.
        JsonObject Rejects() => new()
        {
            ["browser"] = new JsonArray(new JsonObject
            {
                ["match"] = s.Op("/connect/authorize*"),
                ["tasks"] = new JsonArray(
                    Task("Cancel login", s.Op("/account/login*"), false, Command("click", "id", "login-cancel")),
                    VerifyCallback()),
            }),
        };
        return new JsonObject
        {
            ["fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"] = ReusedRequestUri(),
            ["fapi1-advanced-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"] = ReusedRequestUri(),
            ["fapi2-security-profile-final-user-rejects-authentication"] = Rejects(),
            ["fapi1-advanced-final-user-rejects-authentication"] = Rejects(),
        };
    }

    /// <summary>Per-test browser instructions for the OpenID Connect plans.</summary>
    public static JsonObject OidccOverrides(ConformanceSettings s)
    {
        var overrides = new JsonObject();
        foreach (var test in new[] { "oidcc-prompt-login", "oidcc-max-age-1" })
            overrides[test] = new JsonObject { ["browser"] = new JsonArray([.. Authorize(s, loginScreenshot: true).Select(n => n!.DeepClone()), EndSession(s)]) };

        // Client metadata shown to the End-User (OIDC Registration §2): screenshot the consent page.
        foreach (var test in new[] { "oidcc-registration-logo-uri", "oidcc-registration-policy-uri", "oidcc-registration-tos-uri" })
            overrides[test] = new JsonObject { ["browser"] = new JsonArray([.. Authorize(s, consentScreenshot: true).Select(n => n!.DeepClone())]) };

        foreach (var test in new[]
                 {
                     "oidcc-ensure-registered-redirect-uri", "oidcc-ensure-redirect-uri-in-authorization-request",
                     "oidcc-redirect-uri-query-added", "oidcc-redirect-uri-query-mismatch",
                     "oidcc-ensure-request-object-with-redirect-uri",
                 })
            overrides[test] = ErrorPage(s, "/connect/authorize*");

        // RP-Initiated Logout tests that end on the OP rather than at the relying party.
        foreach (var test in new[]
                 {
                     "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
                     "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
                     "oidcc-rp-initiated-logout-modified-id-token-hint",
                 })
            overrides[test] = ErrorPage(s, "/connect/end_session*", signInFirst: true);
        foreach (var test in new[]
                 {
                     "oidcc-rp-initiated-logout-no-post-logout-redirect-uri",
                     "oidcc-rp-initiated-logout-no-params",
                 })
            overrides[test] = LogoutPage(s, "signed out");
        return overrides;
    }
}
