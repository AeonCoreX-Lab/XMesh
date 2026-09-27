using XMesh.Assets;
using XMesh.Cache;
using XMesh.Core;
using XMesh.Security;
using Xunit;

namespace XMesh.Tests;

public class CacheTests
{
    [Fact]
    public async Task Chunks_written_out_of_order_assemble_into_identical_file()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 5 + 123);
        var m = Fixture.Manifest(data, pub);
        var cache = new AssetCache(t.Sub("c"), long.MaxValue);

        using (var s = cache.OpenSession(m))
        {
            foreach (var i in new[] { 5, 0, 3, 1, 4, 2 })
                await s.WriteChunkAsync(i, data.AsMemory(i * 4096, m.ChunkLength(i)));
            await s.FinalizeAsync();
        }
        Assert.True(cache.IsComplete(m));
        Assert.Equal(data, await File.ReadAllBytesAsync(cache.FinalPath(m.AssetId, m.Version)));
    }

    [Fact]
    public async Task Corrupt_chunk_is_rejected_and_never_written()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 3);
        var m = Fixture.Manifest(data, pub);
        var cache = new AssetCache(t.Sub("c"), long.MaxValue);
        using var s = cache.OpenSession(m);

        var bad = data.AsSpan(0, 4096).ToArray(); bad[10] ^= 0xFF;
        var ex = await Assert.ThrowsAsync<XMeshException>(() => s.WriteChunkAsync(0, bad));
        Assert.Equal(XMeshErrorCode.ChunkHashMismatch, ex.Code);
        Assert.False(s.Has(0));
        Assert.Equal(0, s.CompletedCount);
    }

    [Fact]
    public async Task Wrong_length_chunk_is_rejected()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 2);
        var m = Fixture.Manifest(data, pub);
        using var s = new AssetCache(t.Sub("c"), long.MaxValue).OpenSession(m);
        await Assert.ThrowsAsync<XMeshException>(() => s.WriteChunkAsync(0, data.AsMemory(0, 100)));
    }

    [Fact]
    public async Task Resume_after_interruption_keeps_verified_chunks_and_only_needs_the_rest()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 20);
        var m = Fixture.Manifest(data, pub);
        var cache = new AssetCache(t.Sub("c"), long.MaxValue);

        using (var s1 = cache.OpenSession(m))
        {
            for (int i = 0; i < 12; i++) await s1.WriteChunkAsync(i, data.AsMemory(i * 4096, 4096));
        } // disposed => state persisted, simulating a crash/interruption

        using var s2 = cache.OpenSession(m);
        Assert.Equal(12, s2.CompletedCount);
        Assert.Equal(Enumerable.Range(12, 8), s2.Missing());
        for (int i = 12; i < 20; i++) await s2.WriteChunkAsync(i, data.AsMemory(i * 4096, 4096));
        await s2.FinalizeAsync();
        Assert.Equal(data, await File.ReadAllBytesAsync(cache.FinalPath(m.AssetId, m.Version)));
    }

    [Fact]
    public async Task Cannot_finalize_with_missing_chunks()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 3);
        var m = Fixture.Manifest(data, pub);
        using var s = new AssetCache(t.Sub("c"), long.MaxValue).OpenSession(m);
        await s.WriteChunkAsync(0, data.AsMemory(0, 4096));
        await Assert.ThrowsAsync<XMeshException>(() => s.FinalizeAsync());
    }

    [Fact]
    public async Task Concurrent_chunk_writes_do_not_corrupt_the_file()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 64);
        var m = Fixture.Manifest(data, pub);
        var cache = new AssetCache(t.Sub("c"), long.MaxValue);
        using (var s = cache.OpenSession(m))
        {
            await Parallel.ForEachAsync(Enumerable.Range(0, 64), new ParallelOptions { MaxDegreeOfParallelism = 16 },
                async (i, ct) => await s.WriteChunkAsync(i, data.AsMemory(i * 4096, 4096), ct));
            await s.FinalizeAsync();
        }
        Assert.Equal(data, await File.ReadAllBytesAsync(cache.FinalPath(m.AssetId, m.Version)));
    }

    [Fact]
    public async Task Heavy_concurrent_writes_with_frequent_state_saves_never_fail_or_corrupt()
    {
        // Regression test for a real race: concurrent SaveState() calls used to share one temp file
        // ("state.json.tmp"), so writers could collide. Saving after every chunk (stateSaveInterval: 1) with
        // 512 chunks x 64-way parallelism makes hundreds of concurrent SaveState calls.
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 512, 11);
        var m = Fixture.Manifest(data, pub);
        var cache = new AssetCache(t.Sub("c"), long.MaxValue, stateSaveInterval: 1); // save after EVERY chunk

        using (var s = cache.OpenSession(m))
        {
            await Parallel.ForEachAsync(Enumerable.Range(0, 512), new ParallelOptions { MaxDegreeOfParallelism = 64 },
                async (i, ct) => await s.WriteChunkAsync(i, data.AsMemory(i * 4096, 4096), ct));
            Assert.Equal(512, s.CompletedCount);
            await s.FinalizeAsync();
        }
        Assert.Equal(data, await File.ReadAllBytesAsync(cache.FinalPath(m.AssetId, m.Version)));

        // No orphaned temp files and no resurrected state.json after finalization.
        var dir = Path.GetDirectoryName(cache.FinalPath(m.AssetId, m.Version))!;
        Assert.Equal(0, Directory.GetFiles(dir, "*.tmp").Length);
        Assert.False(File.Exists(Path.Combine(dir, "state.json")));
    }

    [Fact]
    public async Task Resume_state_stays_correct_when_saved_concurrently_then_reopened()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 128, 12);
        var m = Fixture.Manifest(data, pub);
        var cache = new AssetCache(t.Sub("c"), long.MaxValue);

        using (var s = cache.OpenSession(m))
        {
            // Write the first 100 chunks concurrently, then "crash" (dispose without finalizing).
            await Parallel.ForEachAsync(Enumerable.Range(0, 100), new ParallelOptions { MaxDegreeOfParallelism = 32 },
                async (i, ct) => await s.WriteChunkAsync(i, data.AsMemory(i * 4096, 4096), ct));
        }

        using var again = cache.OpenSession(m);
        Assert.Equal(100, again.CompletedCount);                 // nothing lost, nothing invented
        Assert.Equal(Enumerable.Range(100, 28), again.Missing());
    }

    // Helper: put a complete 2-chunk asset in the cache and return its measured on-disk size.
    private static async Task<long> PutAsset(AssetCache cache, NodeIdentity pub, string id, int seed)
    {
        var d = Fixture.RandomBytes(4096 * 2, seed);
        var m = Fixture.Manifest(d, pub, id);
        using (var s = cache.OpenSession(m))
        {
            for (int i = 0; i < 2; i++) await s.WriteChunkAsync(i, d.AsMemory(i * 4096, 4096));
            await s.FinalizeAsync();
        }
        return cache.List().Single(a => a.AssetId == id).OnDiskBytes;
    }

    private static void SetAge(AssetCache cache, string id, TimeSpan age) =>
        cache.TouchAt(id, "1.0", DateTime.UtcNow - age);

    [Fact]
    public async Task LRU_eviction_removes_least_recently_used_first_and_stops_once_under_budget()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();

        // Measure the real per-asset footprint instead of guessing, then size the budget to fit exactly 2.
        var probe = new AssetCache(t.Sub("probe"), long.MaxValue);
        long one = await PutAsset(probe, pub, "probe", 9);
        var cache = new AssetCache(t.Sub("c"), maxBytes: one * 2 + one / 2); // room for 2 assets, not 3

        await PutAsset(cache, pub, "a-oldest", 1);
        await PutAsset(cache, pub, "b-middle", 2);
        await PutAsset(cache, pub, "c-newest", 3);
        SetAge(cache, "a-oldest", TimeSpan.FromHours(3));
        SetAge(cache, "b-middle", TimeSpan.FromHours(2));
        SetAge(cache, "c-newest", TimeSpan.FromHours(1));

        long oldestBytes = cache.List().Single(a => a.AssetId == "a-oldest").OnDiskBytes;
        long freed = cache.Evict();

        var left = cache.List().Select(a => a.AssetId).OrderBy(x => x).ToList();
        Assert.Equal(new[] { "b-middle", "c-newest" }, left);   // only the single LRU asset was removed
        Assert.Equal(oldestBytes, freed);                       // and 'freed' is exactly what that asset occupied
    }

    [Fact]
    public async Task Pinned_asset_survives_eviction_even_when_it_is_the_oldest()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var probe = new AssetCache(t.Sub("probe"), long.MaxValue);
        long one = await PutAsset(probe, pub, "probe", 9);
        var cache = new AssetCache(t.Sub("c"), maxBytes: one * 2 + one / 2);

        await PutAsset(cache, pub, "a-oldest", 1);
        await PutAsset(cache, pub, "b-middle", 2);
        await PutAsset(cache, pub, "c-newest", 3);
        SetAge(cache, "a-oldest", TimeSpan.FromHours(3));
        SetAge(cache, "b-middle", TimeSpan.FromHours(2));
        SetAge(cache, "c-newest", TimeSpan.FromHours(1));

        cache.Evict(pinned: new HashSet<string> { "a-oldest@1.0" });

        var left = cache.List().Select(a => a.AssetId).OrderBy(x => x).ToList();
        Assert.Equal(new[] { "a-oldest", "c-newest" }, left);   // pin protected the oldest; next-LRU (b) went instead
    }

    [Fact]
    public async Task Eviction_is_a_no_op_when_under_budget_and_never_touches_partial_downloads()
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var cache = new AssetCache(t.Sub("c"), maxBytes: 1); // absurdly small: everything is over budget

        var d = Fixture.RandomBytes(4096 * 3, 5);
        var m = Fixture.Manifest(d, pub, "partial");
        using (var s = cache.OpenSession(m))
            await s.WriteChunkAsync(0, d.AsMemory(0, 4096));   // 1 of 3 chunks: an in-progress download

        Assert.Equal(0L, cache.Evict());                        // partial asset is not evictable
        Assert.Equal(1, cache.List().Count);
    }

    [Fact]
    public void Path_traversal_in_cache_is_blocked()
    {
        using var t = new TempDir();
        var cache = new AssetCache(t.Sub("c"), long.MaxValue);
        Assert.Throws<XMeshException>(() => cache.FinalPath("../../etc", "passwd"));
    }
}
