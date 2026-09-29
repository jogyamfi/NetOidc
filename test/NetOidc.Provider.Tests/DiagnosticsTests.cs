using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using NetOidc.Provider.Abstractions.Events;
using NetOidc.Provider.Dcr;
using NetOidc.Provider.Diagnostics;
using NetOidc.Provider.Jose;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P4.2 (logging and events) and P4.6 (telemetry and health).</summary>
public sealed class DiagnosticsTests
{
    private sealed class RecordingSink : IProviderEventSink
    {
        public ConcurrentQueue<object> Events { get; } = new();

        private Task Add(object e) { Events.Enqueue(e); return Task.CompletedTask; }

        public Task TokenIssuedAsync(TokenIssuedEvent e, CancellationToken ct = default) => Add(e);
        public Task AuthorizationSucceededAsync(AuthorizationSucceededEvent e, CancellationToken ct = default) => Add(e);
        public Task TokenIntrospectedAsync(TokenIntrospectedEvent e, CancellationToken ct = default) => Add(e);
        public Task TokenRevokedAsync(TokenRevokedEvent e, CancellationToken ct = default) => Add(e);
        public Task UserInfoRequestedAsync(UserInfoRequestedEvent e, CancellationToken ct = default) => Add(e);
        public Task ClientAuthenticationFailedAsync(ClientAuthenticationFailedEvent e, CancellationToken ct = default) => Add(e);
        public Task TokenRequestFailedAsync(TokenRequestFailedEvent e, CancellationToken ct = default) => Add(e);
        public Task AuthorizationFailedAsync(AuthorizationFailedEvent e, CancellationToken ct = default) => Add(e);
        public Task LoggedOutAsync(LoggedOutEvent e, CancellationToken ct = default) => Add(e);
        public Task AuthorizationDecisionAsync(AuthorizationDecisionEvent e, CancellationToken ct = default) => Add(e);
        public Task ClientRegistrationChangedAsync(ClientRegistrationChangedEvent e, CancellationToken ct = default) => Add(e);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new Logger(this);
        public void Dispose() { }

        private sealed class Logger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex, Func<TState, Exception?, string> formatter) =>
                owner.Messages.Enqueue(formatter(state, ex) + " " + ex);
        }
    }

    private static TestWebApp CreateApp(RecordingSink sink, CapturingLoggerProvider? logs = null,
        Action<Configuration.ProviderOptions>? configure = null) =>
        TestWebApp.Create(configure, b =>
        {
            b.Services.AddSingleton<IProviderEventSink>(sink);
            if (logs is not null) b.Services.AddSingleton<ILoggerProvider>(logs);
        });

    // ── P4.2 Events ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FailureEvents_AreRaised()
    {
        var sink = new RecordingSink();
        await using var app = CreateApp(sink);

        await Oidc.TokenAsync(app, [new("grant_type", "client_credentials")], ("cc-client", "wrong"));
        await Oidc.TokenAsync(app, [new("grant_type", "authorization_code"), new("code", "bogus")], ("test-client", "test-secret"));
        await Oidc.AuthorizeAsync(app, ("client_id", "test-client"), ("response_type", "code"), ("scope", "openid"),
            ("redirect_uri", Oidc.Callback), ("prompt", "none"));

        var authFailure = Assert.Single(sink.Events.OfType<ClientAuthenticationFailedEvent>());
        Assert.Equal("cc-client", authFailure.ClientId);
        Assert.Equal("/connect/token", authFailure.Endpoint);

        var tokenFailure = Assert.Single(sink.Events.OfType<TokenRequestFailedEvent>());
        Assert.Equal(("test-client", "authorization_code", "invalid_grant"),
            (tokenFailure.ClientId, tokenFailure.GrantType, tokenFailure.Error));

        var authzFailure = Assert.Single(sink.Events.OfType<AuthorizationFailedEvent>());
        Assert.Equal("login_required", authzFailure.Error);
    }

    [Fact]
    public async Task LifecycleEvents_AreRaised()
    {
        var sink = new RecordingSink();
        await using var app = CreateApp(sink, configure: o =>
        {
            o.DcrEnabled = true;
            o.LogoutEnabled = true;
            o.DeviceFlowEnabled = true;
        });

        var registration = await app.Client.PostAsJsonAsync("/connect/register",
            new ClientRegistrationRequest { RedirectUris = ["https://rp.example.com/cb"] });
        var clientId = JsonDocument.Parse(await registration.Content.ReadAsStringAsync()).RootElement.GetProperty("client_id").GetString();

        var device = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Post, "/connect/device_authorization")
        {
            Headers = { Authorization = Oidc.Basic("device-client", "device-secret") },
            Content = new FormUrlEncodedContent([new("scope", "openid")]),
        });
        var userCode = JsonDocument.Parse(await device.Content.ReadAsStringAsync()).RootElement.GetProperty("user_code").GetString()!;
        await Oidc.SignInAsync(app, "alice");
        await Phase6Tests.DeviceDecisionAsync(app.Client, userCode, "approve");

        var idToken = (await Oidc.CodeFlowAsync(app)).GetProperty("id_token").GetString()!;
        await app.Client.GetAsync("/connect/end_session?id_token_hint=" + idToken);

        Assert.Contains(sink.Events.OfType<ClientRegistrationChangedEvent>(), e => e.ClientId == clientId && e.Change == "created");
        Assert.Contains(sink.Events.OfType<AuthorizationDecisionEvent>(), e => e.Flow == "device_code" && e.Approved);
        Assert.Contains(sink.Events.OfType<LoggedOutEvent>(), e => e.Subject == "alice");
    }

    [Fact]
    public async Task Logs_NeverContainTokensCodesOrSecrets()
    {
        var sink = new RecordingSink();
        var logs = new CapturingLoggerProvider();
        await using var app = CreateApp(sink, logs);

        var body = await Oidc.CodeFlowAsync(app, scope: "openid profile");
        await Oidc.TokenAsync(app, [new("grant_type", "client_credentials")], ("cc-client", "super-secret-attempt"));

        var secrets = new[]
        {
            body.GetProperty("access_token").GetString()!, body.GetProperty("refresh_token").GetString()!,
            body.GetProperty("id_token").GetString()!, "test-secret", "super-secret-attempt",
        };
        Assert.Contains(logs.Messages, m => m.Contains("Issued authorization_code tokens to client test-client"));
        Assert.Contains(logs.Messages, m => m.Contains("Client authentication failed") && m.Contains("cc-client"));
        foreach (var message in logs.Messages)
            foreach (var secret in secrets)
                Assert.DoesNotContain(secret, message);
    }

    // ── P4.6 Telemetry ──────────────────────────────────────────────────────

    [Fact]
    public async Task EndpointsAreTraced_AndTokensAreCounted()
    {
        var activities = new ConcurrentQueue<Activity>();
        using var activityListener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == NetOidcTelemetry.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activities.Enqueue,
        };
        ActivitySource.AddActivityListener(activityListener);

        var issued = new ConcurrentQueue<string>();
        using var meterListener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == NetOidcTelemetry.Name && instrument.Name == "netoidc.tokens.issued")
                    l.EnableMeasurementEvents(instrument);
            },
        };
        meterListener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var tag in tags)
                if (tag.Key == "grant_type") issued.Enqueue((string)tag.Value!);
        });
        meterListener.Start();

        // A client unique to this test: the listeners are process-wide.
        var sink = new RecordingSink();
        await using var app = CreateApp(sink, configure: o => o.StaticClients =
        [
            .. o.StaticClients,
            new Abstractions.Models.Client
            {
                ClientId = "trace-client",
                ClientSecret = "secret",
                AllowedGrantTypes = ["client_credentials"],
                AllowedScopes = ["profile"],
            },
        ]);
        var resp = await Oidc.TokenAsync(app, [new("grant_type", "client_credentials")], ("trace-client", "secret"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        Assert.Contains(issued, g => g == "client_credentials");
        var trace = Assert.Single(activities, a => a.DisplayName == "NetOidc /connect/token" &&
                                                   (string?)a.GetTagItem("netoidc.client_id") == "trace-client");
        Assert.Equal(200, trace.GetTagItem("http.response.status_code"));
    }

    // ── P4.6 Health ─────────────────────────────────────────────────────────

    private sealed class FixedKeyStore(params ProviderKey[] keys) : IKeyStore
    {
        public IReadOnlyList<ProviderKey> GetKeys() => keys;
    }

    private static ProviderKey Signing(DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, bool generated = false) => new()
    {
        Key = new RsaSecurityKey(RSA.Create(2048)),
        Algorithm = "RS256",
        NotBefore = notBefore,
        NotAfter = notAfter,
        IsGenerated = generated,
    };

    [Fact]
    public async Task KeyHealth_ReflectsTheKeyState()
    {
        async Task<HealthStatus> Check(params ProviderKey[] keys) =>
            (await new KeyHealthCheck(new FixedKeyStore(keys), TimeSpan.FromDays(7))
                .CheckHealthAsync(new HealthCheckContext())).Status;

        var now = DateTimeOffset.UtcNow;
        Assert.Equal(HealthStatus.Healthy, await Check(Signing()));
        Assert.Equal(HealthStatus.Degraded, await Check(Signing(generated: true)));
        Assert.Equal(HealthStatus.Degraded, await Check(Signing(notAfter: now.AddDays(2))));
        Assert.Equal(HealthStatus.Healthy, await Check(Signing(notAfter: now.AddDays(2)), Signing(notBefore: now.AddDays(1))));
        Assert.Equal(HealthStatus.Unhealthy, await Check(Signing(notBefore: now.AddDays(1))));
    }

    [Fact]
    public void HealthCheck_CanBeRegistered()
    {
        var services = new ServiceCollection();
        services.AddHealthChecks().AddNetOidcKeys();
        var options = services.BuildServiceProvider()
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<HealthCheckServiceOptions>>().Value;
        Assert.Contains(options.Registrations, r => r.Name == "netoidc_keys");
    }
}
