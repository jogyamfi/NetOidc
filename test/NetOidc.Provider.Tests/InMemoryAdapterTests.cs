using NetOidc.Provider.Abstractions.Adapters;
using NetOidc.Provider.Abstractions.Models;
using NetOidc.Provider.Adapters;

namespace NetOidc.Provider.Tests;

public sealed class InMemoryAdapterTests
{
    [Fact]
    public async Task ConsumeAsync_IsAtomic_UnderConcurrency()
    {
        for (var round = 0; round < 20; round++)
        {
            var adapter = new InMemoryAdapter<Grant>();
            await adapter.StoreAsync("once", new Grant { GrantId = "once", ClientId = "c", Subject = "u" });

            using var start = new ManualResetEventSlim();
            var tasks = Enumerable.Range(0, 50)
                .Select(_ => Task.Run(async () => { start.Wait(); return await adapter.ConsumeAsync("once"); }))
                .ToArray();
            start.Set();
            var results = await Task.WhenAll(tasks);

            Assert.Single(results, r => r is not null);
        }
    }

    [Fact]
    public async Task ConsumeAsync_ReturnsNull_ForExpiredEntry()
    {
        var adapter = new InMemoryAdapter<Grant>();
        await adapter.StoreAsync("old", new Grant { GrantId = "old", ClientId = "c", Subject = "u" },
            TimeSpan.FromMilliseconds(-1));
        Assert.Null(await adapter.ConsumeAsync("old"));
    }

    [Fact]
    public async Task FindAsync_ReturnsNull_WhenNotStored()
    {
        var adapter = new InMemoryAdapter<Grant>();
        Assert.Null(await adapter.FindAsync("missing"));
    }

    [Fact]
    public async Task StoreAndFind_RoundTrips()
    {
        var adapter = new InMemoryAdapter<Grant>();
        var grant = new Grant { GrantId = "g1", ClientId = "c1", Subject = "u1" };

        await adapter.StoreAsync("g1", grant);
        var found = await adapter.FindAsync("g1");

        Assert.NotNull(found);
        Assert.Equal("u1", found.Subject);
    }

    [Fact]
    public async Task RemoveAsync_DeletesEntry()
    {
        var adapter = new InMemoryAdapter<Grant>();
        var grant = new Grant { GrantId = "g2", ClientId = "c1", Subject = "u1" };
        await adapter.StoreAsync("g2", grant);

        await adapter.RemoveAsync("g2");

        Assert.Null(await adapter.FindAsync("g2"));
    }

    [Fact]
    public async Task ConsumeAsync_RemovesEntryAfterRead()
    {
        var adapter = new InMemoryAdapter<Grant>();
        var grant = new Grant { GrantId = "g3", ClientId = "c1", Subject = "u1" };
        await adapter.StoreAsync("g3", grant);

        var consumed = await adapter.ConsumeAsync("g3");

        Assert.NotNull(consumed);
        Assert.Null(await adapter.FindAsync("g3"));
    }

    [Fact]
    public async Task FindAsync_ReturnsNull_AfterTtlExpired()
    {
        var adapter = new InMemoryAdapter<AccessToken>();
        var token = new AccessToken
        {
            TokenId = "t1",
            GrantId = "g1",
            ClientId = "c1",
            ExpiresAt = DateTimeOffset.UtcNow,
        };

        // Store with a TTL that has already elapsed.
        await adapter.StoreAsync("t1", token, expiresIn: TimeSpan.FromMilliseconds(-1));

        Assert.Null(await adapter.FindAsync("t1"));
    }

    [Fact]
    public async Task ConsumeAsync_ReturnsNull_WhenNotStored()
    {
        var adapter = new InMemoryAdapter<Grant>();
        Assert.Null(await adapter.ConsumeAsync("nonexistent"));
    }
}
