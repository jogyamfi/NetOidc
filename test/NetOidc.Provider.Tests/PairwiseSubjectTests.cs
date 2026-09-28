using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Claims;

namespace NetOidc.Provider.Tests;

/// <summary>Regression tests for REMEDIATION_PLAN P1.11 (pairwise subject identifiers).</summary>
public sealed class PairwiseSubjectTests
{
    private const string Salt = "a-secret-pairwise-salt-of-32-bytes!!";

    [Theory]
    [InlineData(null)]
    [InlineData("short-salt")]
    public void Startup_Fails_WithoutStrongSalt(string? salt)
    {
        var ex = Assert.Throws<OptionsValidationException>(() => TestWebApp.Create(o =>
        {
            o.SubjectType = "pairwise";
            o.PairwiseSalt = salt;
        }));
        Assert.Contains("PairwiseSalt", ex.Message);
    }

    [Fact]
    public void Startup_Fails_ForMultiHostClientWithoutSectorIdentifier()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => TestWebApp.Create(o =>
        {
            o.SubjectType = "pairwise";
            o.PairwiseSalt = Salt;
            o.StaticClients =
            [
                .. o.StaticClients,
                new Client { ClientId = "multi", RedirectUris = ["https://a.example.com/cb", "https://b.example.com/cb"] },
            ];
        }));
        Assert.Contains("SectorIdentifierUri", ex.Message);
    }

    [Fact]
    public async Task Subject_IsStablePerSector_AndDiffersAcrossSectors()
    {
        await using var app = TestWebApp.Create(o =>
        {
            o.SubjectType = "pairwise";
            o.PairwiseSalt = Salt;
        });
        var service = app.Services.GetRequiredService<SubjectIdentifierService>();

        var a1 = service.Compute("alice", new Client { ClientId = "a1", RedirectUris = ["https://rp-a.example.com/cb"] });
        var a2 = service.Compute("alice", new Client { ClientId = "a2", RedirectUris = ["https://rp-a.example.com/other"] });
        var b = service.Compute("alice", new Client { ClientId = "b", RedirectUris = ["https://rp-b.example.com/cb"] });
        var viaSector = service.Compute("alice", new Client
        {
            ClientId = "c",
            SectorIdentifierUri = "https://rp-a.example.com/sector.json",
            RedirectUris = ["https://x.example.com/cb", "https://y.example.com/cb"],
        });

        Assert.Equal(a1, a2);          // same sector → same pairwise sub
        Assert.NotEqual(a1, b);        // different sector → different sub
        Assert.Equal(a1, viaSector);   // sector_identifier_uri host defines the sector
        Assert.NotEqual("alice", a1);
    }

    [Fact]
    public async Task Subject_DependsOnSecretSalt()
    {
        var client = new Client { ClientId = "a", RedirectUris = ["https://rp-a.example.com/cb"] };

        await using var app1 = TestWebApp.Create(o => { o.SubjectType = "pairwise"; o.PairwiseSalt = Salt; });
        await using var app2 = TestWebApp.Create(o => { o.SubjectType = "pairwise"; o.PairwiseSalt = Salt + "-other"; });

        Assert.NotEqual(
            app1.Services.GetRequiredService<SubjectIdentifierService>().Compute("alice", client),
            app2.Services.GetRequiredService<SubjectIdentifierService>().Compute("alice", client));
    }
}
