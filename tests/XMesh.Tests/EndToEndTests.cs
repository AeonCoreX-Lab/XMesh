using System.Net;
using System.Net.Sockets;
using XMesh.Assets;
using XMesh.Core;
using XMesh.Runtime;
using XMesh.Security;
using Xunit;

namespace XMesh.Tests;

/// <summary>Real TCP + TLS + handshake between in-process nodes. No mocks of the network.</summary>
public class EndToEndTests
{
    private static XMeshOptions Opts(string dir, ITrustStore trust, bool serve, params string[] peers) => new()
    {
        DataDir = dir, TrustStore = trust, EnableServing = serve, EnableDiscovery = false,
        StaticPeers = peers,
        Policy = new XMeshPolicy { RequireAllowlist = true, ChunkTimeout = TimeSpan.FromSeconds(10), MaxChunkRetries = 1 },
    };

    private static async Task Seed(XMeshRuntime rt, AssetManifest m, byte[] data)
    {
        using var s = rt.Cache.OpenSession(m);
        for (int i = 0; i < m.ChunkCount; i++) await s.WriteChunkAsync(i, data.AsMemory(i * m.ChunkSize, m.ChunkLength(i)));
        await s.FinalizeAsync();
    }

    [Fact]
    public async Task Node_B_downloads_asset_from_Node_A_over_authenticated_encrypted_channel()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 30 + 77);
        var m = Fixture.Manifest(data, publisher);

        var trustA = new MemoryTrustStore { AllowAllPeers = true };
        var trustB = new MemoryTrustStore { AllowAllPeers = true };
        trustA.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));
        trustB.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));

        await using var a = new XMeshRuntime(Opts(t.Sub("a"), trustA, serve: true));
        await a.StartAsync();
        await Seed(a, m, data);

        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trustB, serve: false, $"127.0.0.1:{a.ListenPort}"));
        await b.StartAsync();

        var r = await b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version) { AllowOrigin = false }, m);
        Assert.True(r.Verified);
        Assert.Equal(m.Size, r.BytesFromPeers);
        Assert.Equal(0, r.BytesFromOrigin);
        Assert.Equal(data, await File.ReadAllBytesAsync(r.LocalPath));
    }

    [Fact]
    public async Task Second_request_is_served_entirely_from_cache_with_no_network()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 8);
        var m = Fixture.Manifest(data, publisher);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));

        await using var a = new XMeshRuntime(Opts(t.Sub("a"), trust, true));
        await a.StartAsync();
        await Seed(a, m, data);
        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trust, false, $"127.0.0.1:{a.ListenPort}"));
        await b.StartAsync();

        await b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version), m);
        await a.DisposeAsync(); // peer gone: offline mode (spec section 39)
        var r2 = await b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version), m);
        Assert.True(r2.ServedEntirelyFromCache);
    }

    [Fact]
    public async Task Peer_not_in_allowlist_is_rejected_and_download_fails_without_origin()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 4);
        var m = Fixture.Manifest(data, publisher);

        var trustA = new MemoryTrustStore(); // A allows nobody
        trustA.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));
        var trustB = new MemoryTrustStore { AllowAllPeers = true };
        trustB.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));

        await using var a = new XMeshRuntime(Opts(t.Sub("a"), trustA, true));
        await a.StartAsync();
        await Seed(a, m, data);
        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trustB, false, $"127.0.0.1:{a.ListenPort}"));
        await b.StartAsync();

        var ex = await Assert.ThrowsAsync<XMeshException>(() =>
            b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version) { AllowOrigin = false }, m));
        Assert.Equal(XMeshErrorCode.OriginUnavailable, ex.Code);

        // Once A allows B, the same request succeeds.
        trustA.AllowPeer(b.Identity.Id);
        var r = await b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version) { AllowOrigin = false }, m);
        Assert.Equal(data, await File.ReadAllBytesAsync(r.LocalPath));
    }

    [Fact]
    public async Task Untrusted_publisher_manifest_is_refused_before_any_network_activity()
    {
        using var t = new TempDir();
        using var attacker = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 2);
        var m = Fixture.Manifest(data, attacker);
        var trust = new MemoryTrustStore { AllowAllPeers = true }; // does NOT trust the attacker

        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trust, false));
        await b.StartAsync();
        var ex = await Assert.ThrowsAsync<XMeshException>(() => b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version), m));
        Assert.Equal(XMeshErrorCode.ManifestSignatureInvalid, ex.Code);
    }

    [Fact]
    public async Task Dead_peer_falls_back_to_origin_and_still_verifies()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 10 + 5);

        using var origin = new TestOrigin(data);
        var m = Fixture.Manifest(data, publisher, origin: origin.Url);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));

        int deadPort = FreePort();
        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trust, false, $"127.0.0.1:{deadPort}"));
        await b.StartAsync();
        var r = await b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version), m);

        Assert.Equal(0, r.BytesFromPeers);
        Assert.Equal(m.Size, r.BytesFromOrigin);
        Assert.Equal(data, await File.ReadAllBytesAsync(r.LocalPath));
    }

    [Fact]
    public async Task Origin_serving_corrupted_bytes_is_detected_and_never_cached()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 4);
        var evil = (byte[])data.Clone(); evil[5000] ^= 0xFF; // one flipped byte inside chunk 1

        using var origin = new TestOrigin(evil);
        var m = Fixture.Manifest(data, publisher, origin: origin.Url);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));

        var opts = Opts(t.Sub("b"), trust, false) with { Policy = new XMeshPolicy { MaxChunkRetries = 0, RequireAllowlist = false } };
        await using var b = new XMeshRuntime(opts);
        await b.StartAsync();
        await Assert.ThrowsAsync<XMeshException>(() => b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version), m));
        Assert.False(b.Cache.IsComplete(m));
    }

    [Fact]
    public async Task Poisoned_peer_is_dropped_and_origin_completes_the_download()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var good = Fixture.RandomBytes(4096 * 6);
        var m = Fixture.Manifest(good, publisher);

        // Peer A holds a manifest-matching cache whose chunk bytes are silently corrupted on disk.
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));
        await using var a = new XMeshRuntime(Opts(t.Sub("a"), trust, true));
        await a.StartAsync();
        await Seed(a, m, good);
        var dataFile = a.Cache.FinalPath(m.AssetId, m.Version);
        var bytes = await File.ReadAllBytesAsync(dataFile);
        bytes[4096 * 2 + 1] ^= 0xFF; // corrupt chunk 2 on disk
        await File.WriteAllBytesAsync(dataFile, bytes);

        using var origin = new TestOrigin(good);
        var withOrigin = Fixture.Manifest(good, publisher, origin: origin.Url);
        // same content => same root, so peers still recognise it

        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trust, false, $"127.0.0.1:{a.ListenPort}"));
        await b.StartAsync();
        var r = await b.GetAssetAsync(new AssetRequest(withOrigin.AssetId, withOrigin.Version), withOrigin);

        Assert.True(r.Verified);
        Assert.Equal(good, await File.ReadAllBytesAsync(r.LocalPath));
        Assert.True(r.BytesFromOrigin >= 4096); // the corrupt chunk had to come from origin
    }

    [Fact]
    public async Task Interrupted_download_resumes_using_previously_verified_chunks()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 20);
        using var origin = new TestOrigin(data);
        var m = Fixture.Manifest(data, publisher, origin: origin.Url);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));

        var dir = t.Sub("b");
        await using (var b1 = new XMeshRuntime(Opts(dir, trust, false)))
        {
            await b1.StartAsync();
            // Simulate a previous partial download: 12 of 20 chunks already verified on disk.
            using var s = b1.Cache.OpenSession(m);
            for (int i = 0; i < 12; i++) await s.WriteChunkAsync(i, data.AsMemory(i * 4096, 4096));
        }

        await using var b2 = new XMeshRuntime(Opts(dir, trust, false));
        await b2.StartAsync();
        var r = await b2.GetAssetAsync(new AssetRequest(m.AssetId, m.Version), m);
        Assert.Equal(12L * 4096, r.BytesFromCache);
        Assert.Equal(8L * 4096, r.BytesFromOrigin);
        Assert.Equal(data, await File.ReadAllBytesAsync(r.LocalPath));
    }

    [Fact]
    public async Task Concurrent_requests_for_same_asset_share_one_transfer()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 12);
        using var origin = new TestOrigin(data);
        var m = Fixture.Manifest(data, publisher, origin: origin.Url);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));
        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trust, false));
        await b.StartAsync();

        var req = new AssetRequest(m.AssetId, m.Version);
        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => b.GetAssetAsync(req, m)));
        Assert.All(results, r => Assert.Equal(results[0].LocalPath, r.LocalPath));
        Assert.Equal(m.ChunkCount, origin.RequestCount); // each chunk fetched from origin exactly once
    }

    [Fact]
    public async Task No_listener_is_opened_when_serving_is_disabled_by_policy()
    {
        using var t = new TempDir();
        using var publisher = NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 3);
        var m = Fixture.Manifest(data, publisher);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(publisher.PublicKeySpki));

        // A is a server node but with serving disabled => no listener at all.
        var a = Opts(t.Sub("a"), trust, true) with { Policy = new XMeshPolicy { AllowServing = false, RequireAllowlist = false } };
        await using var rtA = new XMeshRuntime(a);
        await rtA.StartAsync();
        Assert.Equal(0, rtA.ListenPort);
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p;
    }
}

/// <summary>
/// Real-time throttling checks over real sockets. Bounds are deliberately generous (CI machines are noisy);
/// what they prove is ORDER OF MAGNITUDE: a limited transfer is slower by roughly the configured factor,
/// and an unlimited one is not throttled at all.
/// </summary>
public class ThrottleEndToEndTests
{
    private static XMeshOptions Opts(string dir, ITrustStore trust, bool serve, XMeshPolicy policy, params string[] peers) => new()
    {
        DataDir = dir, TrustStore = trust, EnableServing = serve, EnableDiscovery = false, StaticPeers = peers, Policy = policy,
    };

    private static async Task Seed(XMeshRuntime rt, AssetManifest m, byte[] data)
    {
        using var s = rt.Cache.OpenSession(m);
        for (int i = 0; i < m.ChunkCount; i++) await s.WriteChunkAsync(i, data.AsMemory(i * m.ChunkSize, m.ChunkLength(i)));
        await s.FinalizeAsync();
    }

    private static async Task<double> Timed(long uploadLimit, long downloadLimit, byte[] data)
    {
        using var t = new TempDir();
        using var pub = NodeIdentity.Generate();
        var m = Fixture.Manifest(data, pub, chunkSize: 16384);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(pub.PublicKeySpki));

        await using var a = new XMeshRuntime(Opts(t.Sub("a"), trust, true,
            new XMeshPolicy { RequireAllowlist = false, MaxUploadBytesPerSecond = uploadLimit }));
        await a.StartAsync();
        await Seed(a, m, data);

        await using var b = new XMeshRuntime(Opts(t.Sub("b"), trust, false,
            new XMeshPolicy { RequireAllowlist = false, MaxDownloadBytesPerSecond = downloadLimit }, $"127.0.0.1:{a.ListenPort}"));
        await b.StartAsync();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await b.GetAssetAsync(new AssetRequest(m.AssetId, m.Version) { AllowOrigin = false }, m);
        sw.Stop();
        Assert.Equal(data, await File.ReadAllBytesAsync(r.LocalPath));   // throttling must never corrupt data
        return sw.Elapsed.TotalSeconds;
    }

    [Fact]
    public async Task Upload_limit_slows_the_server_and_data_is_still_exact()
    {
        var data = Fixture.RandomBytes(400_000, 21);                     // 400 KB
        double free = await Timed(uploadLimit: 0, downloadLimit: 0, data);
        double limited = await Timed(uploadLimit: 100_000, downloadLimit: 0, data);   // 100 KB/s
        // 400 KB at 100 KB/s with a 1 s burst => ~3 s. Unlimited over loopback is milliseconds.
        Assert.True(limited >= 2.0, $"upload limit had no effect: {limited:F2}s (unlimited took {free:F2}s)");
        Assert.True(limited <= 8.0, $"upload limit far too strict: {limited:F2}s");
        Assert.True(free < 1.5, $"unlimited run was unexpectedly slow: {free:F2}s");
    }

    [Fact]
    public async Task Download_limit_slows_the_client_and_data_is_still_exact()
    {
        var data = Fixture.RandomBytes(400_000, 22);
        double limited = await Timed(uploadLimit: 0, downloadLimit: 100_000, data);
        Assert.True(limited >= 2.0, $"download limit had no effect: {limited:F2}s");
        Assert.True(limited <= 8.0, $"download limit far too strict: {limited:F2}s");
    }

    [Fact]
    public void Legacy_MaxBandwidth_applies_to_both_directions_unless_overridden()
    {
        var both = new XMeshPolicy { MaxBandwidthBytesPerSecond = 500 };
        Assert.Equal(500L, both.EffectiveUploadLimit);
        Assert.Equal(500L, both.EffectiveDownloadLimit);

        var mixed = new XMeshPolicy { MaxBandwidthBytesPerSecond = 500, MaxUploadBytesPerSecond = 50 };
        Assert.Equal(50L, mixed.EffectiveUploadLimit);
        Assert.Equal(500L, mixed.EffectiveDownloadLimit);

        var explicitUnlimited = new XMeshPolicy { MaxBandwidthBytesPerSecond = 500, MaxDownloadBytesPerSecond = 0 };
        Assert.Equal(0L, explicitUnlimited.EffectiveDownloadLimit);     // 0 must mean unlimited, not "fall back"
    }
}

/// <summary>
/// Real-socket proof that hedging actually helps: a straggler peer must not hold up the whole
/// download when a healthy peer could serve the same chunk just as well (spec section 41).
///
/// Both peers hold the FULL asset (this matters: if one peer only had a subset, a worker connecting to
/// it would just decline everything it lacks and exit - that is peer diversity working normally, not a
/// straggler). The only difference is the throttled peer's upload cap, so contention is on whichever
/// chunk it happens to be serving when the fast peer runs out of other work.
/// </summary>
public class HedgingEndToEndTests
{
    private static async Task Seed(XMeshRuntime rt, AssetManifest m, byte[] d)
    {
        using var s = rt.Cache.OpenSession(m);
        for (int i = 0; i < m.ChunkCount; i++) await s.WriteChunkAsync(i, d.AsMemory(i * m.ChunkSize, m.ChunkLength(i)));
        await s.FinalizeAsync();
    }

    private static async Task<double> RunWithBothPeers(TempDir t, bool hedge, MemoryTrustStore trust, AssetManifest m, byte[] data,
        string dataDir, int slowPort, int fastPort)
    {
        await using var c = new XMeshRuntime(new XMeshOptions
        {
            DataDir = t.Sub(dataDir), TrustStore = trust, EnableServing = false, EnableDiscovery = false,
            StaticPeers = new[] { $"127.0.0.1:{slowPort}", $"127.0.0.1:{fastPort}" },
            HedgeSlowChunks = hedge, HedgeAfter = TimeSpan.FromMilliseconds(200),
            Policy = new XMeshPolicy { RequireAllowlist = false, ChunkTimeout = TimeSpan.FromSeconds(20) },
        });
        await c.StartAsync();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await c.GetAssetAsync(new AssetRequest(m.AssetId, m.Version) { AllowOrigin = false }, m);
        sw.Stop();
        Assert.Equal(data, await File.ReadAllBytesAsync(r.LocalPath));   // hedging races two sources: data must still be exact
        return sw.Elapsed.TotalSeconds;
    }

    /// <summary>
    /// Starts a FRESH 'slow' (throttled) and 'fast' (unthrottled) peer pair, both holding the full asset.
    /// A fresh pair per comparison run matters: the upload RateLimiter lives for the runtime's lifetime, so
    /// reusing one 'slow' peer across two runs lets the FIRST run's unspent bandwidth debt bleed into the
    /// SECOND run and skew the comparison - this bit us once (a "hedging is slower" false result that was
    /// really "peer serving the second call is still paying off debt from the first call").
    /// </summary>
    private static async Task<(XMeshRuntime Slow, XMeshRuntime Fast)> FreshPeerPair(TempDir t, string tag, MemoryTrustStore trust, AssetManifest m, byte[] data)
    {
        var slow = new XMeshRuntime(new XMeshOptions { DataDir = t.Sub("slow" + tag), TrustStore = trust,
            EnableServing = true, EnableDiscovery = false, Policy = new XMeshPolicy { RequireAllowlist = false, MaxUploadBytesPerSecond = 8_000 } });
        await slow.StartAsync(); await Seed(slow, m, data);
        var fast = new XMeshRuntime(new XMeshOptions { DataDir = t.Sub("fast" + tag), TrustStore = trust,
            EnableServing = true, EnableDiscovery = false, Policy = new XMeshPolicy { RequireAllowlist = false } });
        await fast.StartAsync(); await Seed(fast, m, data);
        return (slow, fast);
    }

    [Fact]
    public async Task Hedging_lets_a_fast_peer_pick_up_whatever_the_slow_peer_is_dawdling_on()
    {
        using var t = new TempDir(); using var pub = NodeIdentity.Generate();
        // MANY chunks, LARGE enough that a single one takes real time even for 'slow' alone: with 40 tiny
        // chunks, 'fast' answers almost every request in under a millisecond, so it always beats 'slow' to
        // its NEXT chunk request too - 'slow' never gets any exclusive, uncontested work, and the whole
        // asset finishes at 'fast' speed regardless of hedging. Larger chunks make each individual transfer
        // (whichever peer serves it) take long enough that hedging's benefit - reassigning ONE stuck chunk -
        // is clearly visible against the baseline where that one chunk fully serializes behind 'slow'.
        var data = Fixture.RandomBytes(65536 * 8, 61);
        var m = Fixture.Manifest(data, pub, chunkSize: 65536);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(pub.PublicKeySpki));

        // Independent peer pairs per run (see FreshPeerPair) so neither run's bandwidth debt leaks into the other.
        var (slowA, fastA) = await FreshPeerPair(t, "A", trust, m, data);
        await using var _sA = slowA; await using var _fA = fastA;
        double withoutHedging = await RunWithBothPeers(t, false, trust, m, data, "cA", slowA.ListenPort, fastA.ListenPort);

        var (slowB, fastB) = await FreshPeerPair(t, "B", trust, m, data);
        await using var _sB = slowB; await using var _fB = fastB;
        double withHedging = await RunWithBothPeers(t, true, trust, m, data, "cB", slowB.ListenPort, fastB.ListenPort);

        Assert.True(withoutHedging >= 0.7, $"expected 'slow' to noticeably extend the tail without hedging, got {withoutHedging:F2}s");
        Assert.True(withHedging <= withoutHedging, $"hedging ({withHedging:F2}s) should never be slower than not hedging ({withoutHedging:F2}s)");
        Assert.True(withHedging < withoutHedging * 0.85, $"hedging ({withHedging:F2}s) was not meaningfully faster than no hedging ({withoutHedging:F2}s)");
    }
}
