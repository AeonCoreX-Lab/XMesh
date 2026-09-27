using System.Security.Cryptography;
using XMesh.Assets;
using XMesh.Core;
using XMesh.Protocol;
using XMesh.Runtime;
using XMesh.Security;
using Xunit;

namespace XMesh.Tests;

public class PooledBufferTests
{
    [Fact]
    public void Exposes_exactly_the_requested_length_not_the_rented_array()
    {
        using var b = PooledBuffer.Rent(1000);          // pool rounds the array up (e.g. 1024)
        Assert.Equal(1000, b.Length);
        Assert.Equal(1000, b.Memory.Length);
        Assert.Equal(1000, b.Span.Length);
        Assert.Equal(1000, b.ToArray().Length);
    }

    [Fact]
    public void Dispose_is_idempotent_and_never_double_returns()
    {
        long before = PooledBuffer.Outstanding;
        var b = PooledBuffer.Rent(64);
        Assert.Equal(before + 1, PooledBuffer.Outstanding);
        b.Dispose(); b.Dispose(); b.Dispose();
        Assert.Equal(before, PooledBuffer.Outstanding);   // decremented exactly once
    }

    [Fact]
    public void Use_after_dispose_fails_loudly()
    {
        var b = PooledBuffer.Rent(16);
        b.Dispose();
        Assert.True(b.IsDisposed);
        Assert.Throws<ObjectDisposedException>(() => { var _ = b.Memory; });
        Assert.Throws<ObjectDisposedException>(() => { var _ = b.Span.Length; });
        Assert.Throws<ObjectDisposedException>(() => b.ToArray());
    }

    [Fact]
    public void ToArray_survives_disposal_and_is_independent()
    {
        var b = PooledBuffer.Rent(4);
        new byte[] { 1, 2, 3, 4 }.CopyTo(b.Span);
        var copy = b.ToArray();
        b.Dispose();
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, copy);
    }

    [Fact]
    public void Zero_length_and_negative_length()
    {
        using var z = PooledBuffer.Rent(0);
        Assert.Equal(0, z.Length);
        Assert.Throws<ArgumentOutOfRangeException>(() => PooledBuffer.Rent(-1));
    }

    [Fact]
    public void Sensitive_buffers_can_be_zeroed_on_return()
    {
        var pool = System.Buffers.ArrayPool<byte>.Create();
        var b = PooledBuffer.Rent(32, clearOnReturn: true, pool: pool);
        var backing = System.Runtime.InteropServices.MemoryMarshal.TryGetArray<byte>(b.Memory, out var seg) ? seg.Array! : null;
        Assert.NotNull(backing);
        b.Span.Fill(0xAB);
        b.Dispose();
        Assert.True(backing!.AsSpan(0, 32).ToArray().All(x => x == 0), "buffer was not cleared on return");
    }
}

public class PooledReceiveTests
{
    [Fact]
    public async Task Pooled_read_matches_the_normal_read_and_bounds_the_length_first()
    {
        var data = new byte[5000]; new Random(4).NextBytes(data);
        var wire = Frame.Encode(MessageType.Chunk, new ChunkMessage(2, data).Encode());

        var normal = await Frame.ReadAsync(new MemoryStream(wire), Frame.MaxPayload, default);
        using var pooled = (await Frame.ReadPooledAsync(new MemoryStream(wire), Frame.MaxPayload, default))!.Value.Payload;
        Assert.Equal(normal!.Value.Payload, pooled.ToArray());

        // Oversized claim is rejected BEFORE renting anything.
        long before = PooledBuffer.Outstanding;
        var hdr = Frame.Encode(MessageType.Chunk, Array.Empty<byte>());
        hdr[5] = 0x7F; hdr[6] = 0xFF; hdr[7] = 0xFF; hdr[8] = 0xFF;
        await Assert.ThrowsAsync<XMeshException>(() => Frame.ReadPooledAsync(new MemoryStream(hdr), Frame.MaxPayload, default));
        Assert.Equal(before, PooledBuffer.Outstanding);
    }

    [Fact]
    public async Task Truncated_pooled_read_does_not_leak_the_rented_buffer()
    {
        long before = PooledBuffer.Outstanding;
        var wire = Frame.Encode(MessageType.Chunk, new byte[1000]);
        var cut = wire[..^100];                                     // header promises 1000, only 900 arrive
        await Assert.ThrowsAnyAsync<Exception>(() => Frame.ReadPooledAsync(new MemoryStream(cut), Frame.MaxPayload, default));
        Assert.Equal(before, PooledBuffer.Outstanding);
    }

    [Fact]
    public void ChunkWire_parse_rejects_inconsistent_lengths()
    {
        var good = new ChunkMessage(1, new byte[10]).Encode();
        ChunkWire.Parse(good, out var d); Assert.Equal(10, d.Length);

        var lying = (byte[])good.Clone(); lying[7] = 99;            // claims 99 data bytes, only 10 present
        Assert.Throws<XMeshException>(() => { ChunkWire.Parse(lying, out _); });
        var trailing = good.Concat(new byte[] { 0 }).ToArray();     // extra byte after the data
        Assert.Throws<XMeshException>(() => { ChunkWire.Parse(trailing, out _); });
        var negative = (byte[])good.Clone(); negative[4] = 0xFF; negative[5] = 0xFF; negative[6] = 0xFF; negative[7] = 0xFF;
        Assert.Throws<XMeshException>(() => { ChunkWire.Parse(negative, out _); });
    }
}

/// <summary>The important one: after real transfers - including hostile ones - not a single pooled buffer may be outstanding.</summary>
public class PoolLeakEndToEndTests
{
    private static XMeshOptions Opts(string dir, ITrustStore t, bool serve, params string[] peers) => new()
    {
        DataDir = dir, TrustStore = t, EnableServing = serve, EnableDiscovery = false, StaticPeers = peers,
        Policy = new XMeshPolicy { RequireAllowlist = false, MaxChunkRetries = 1, ChunkTimeout = TimeSpan.FromSeconds(10) },
    };

    private static async Task Seed(XMeshRuntime rt, AssetManifest m, byte[] d)
    {
        using var s = rt.Cache.OpenSession(m);
        for (int i = 0; i < m.ChunkCount; i++) await s.WriteChunkAsync(i, d.AsMemory(i * m.ChunkSize, m.ChunkLength(i)));
        await s.FinalizeAsync();
    }

    [Fact]
    public async Task No_buffers_leak_after_success_a_poisoned_peer_and_a_dead_peer()
    {
        long baseline = PooledBuffer.Outstanding;

        using var t = new TempDir(); using var pub = NodeIdentity.Generate();
        var good = Fixture.RandomBytes(4096 * 24 + 9, 31);
        var trust = new MemoryTrustStore { AllowAllPeers = true };
        trust.TrustPublisher(Fixture.Hex(pub.PublicKeySpki));

        // --- happy path
        var m1 = Fixture.Manifest(good, pub, "ok");
        await using (var a = new XMeshRuntime(Opts(t.Sub("a1"), trust, true)))
        {
            await a.StartAsync(); await Seed(a, m1, good);
            await using var b = new XMeshRuntime(Opts(t.Sub("b1"), trust, false, $"127.0.0.1:{a.ListenPort}"));
            await b.StartAsync();
            var r = await b.GetAssetAsync(new AssetRequest("ok", "1.0") { AllowOrigin = false }, m1);
            Assert.Equal(good, await File.ReadAllBytesAsync(r.LocalPath));   // the happy path must really have transferred
        }

        // --- poisoned peer: corrupt chunk on disk => HashMismatch path inside the loop
        var m2 = Fixture.Manifest(good, pub, "poison");
        using var origin = new TestOrigin(good);
        var m2o = Fixture.Manifest(good, pub, "poison", origin: origin.Url);
        await using (var a = new XMeshRuntime(Opts(t.Sub("a2"), trust, true)))
        {
            await a.StartAsync(); await Seed(a, m2, good);
            var f = a.Cache.FinalPath("poison", "1.0");
            var bytes = await File.ReadAllBytesAsync(f); bytes[4096 * 3 + 5] ^= 0xFF; await File.WriteAllBytesAsync(f, bytes);
            await using var b = new XMeshRuntime(Opts(t.Sub("b2"), trust, false, $"127.0.0.1:{a.ListenPort}"));
            await b.StartAsync();
            var r = await b.GetAssetAsync(new AssetRequest("poison", "1.0"), m2o);
            Assert.Equal(good, await File.ReadAllBytesAsync(r.LocalPath));
        }

        // --- dead peer + failing origin: exception path
        var m3 = Fixture.Manifest(good, pub, "dead");
        await using (var b = new XMeshRuntime(Opts(t.Sub("b3"), trust, false, "127.0.0.1:1")))
        {
            await b.StartAsync();
            await Assert.ThrowsAsync<XMeshException>(() => b.GetAssetAsync(new AssetRequest("dead", "1.0") { AllowOrigin = false }, m3));
        }

        // Give any in-flight server-side handlers a moment to unwind, then require zero outstanding.
        for (int i = 0; i < 50 && PooledBuffer.Outstanding != baseline; i++) await Task.Delay(50);
        Assert.Equal(baseline, PooledBuffer.Outstanding);
    }
}

public class OriginClientTests
{
    [Fact]
    public async Task Public_GetChunkAsync_still_returns_the_real_bytes()
    {
        // Guards against a refactor that "succeeds" but hands back an empty array.
        var data = Fixture.RandomBytes(4096 * 5 + 200, 41);
        using var pub = XMesh.Security.NodeIdentity.Generate();
        using var origin = new TestOrigin(data);
        var m = Fixture.Manifest(data, pub, origin: origin.Url);
        using var oc = new XMesh.Transport.OriginClient();

        for (int i = 0; i < m.ChunkCount; i++)
        {
            var got = await oc.GetChunkAsync(m, i, default);
            Assert.Equal(m.ChunkLength(i), got.Length);
            Assert.Equal(data.AsSpan(i * 4096, m.ChunkLength(i)).ToArray(), got);
        }
    }

    [Fact]
    public async Task Pooled_fetch_matches_the_array_fetch_and_is_returned_cleanly()
    {
        var data = Fixture.RandomBytes(4096 * 3 + 17, 42);
        using var pub = XMesh.Security.NodeIdentity.Generate();
        using var origin = new TestOrigin(data);
        var m = Fixture.Manifest(data, pub, origin: origin.Url);
        using var oc = new XMesh.Transport.OriginClient();

        long before = PooledBuffer.Outstanding;
        for (int i = 0; i < m.ChunkCount; i++)
        {
            using var lease = await oc.GetChunkPooledAsync(m, i, default);
            Assert.Equal(data.AsSpan(i * 4096, m.ChunkLength(i)).ToArray(), lease.ToArray());
        }
        Assert.Equal(before, PooledBuffer.Outstanding);
    }

    [Fact]
    public async Task Failed_pooled_fetch_does_not_leak_the_lease()
    {
        using var pub = XMesh.Security.NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 2, 43);
        // Origin URL points at a dead port => connection failure.
        var m = Fixture.Manifest(data, pub, origin: "http://127.0.0.1:1/asset.bin");
        using var oc = new XMesh.Transport.OriginClient();
        long before = PooledBuffer.Outstanding;
        await Assert.ThrowsAsync<XMeshException>(() => oc.GetChunkPooledAsync(m, 0, default));
        Assert.Equal(before, PooledBuffer.Outstanding);
    }

    [Fact]
    public async Task Origin_that_sends_too_few_bytes_is_a_retryable_origin_error_and_leaks_nothing()
    {
        using var pub = XMesh.Security.NodeIdentity.Generate();
        var data = Fixture.RandomBytes(4096 * 2, 44);
        using var origin = new TestOrigin(data.AsSpan(0, 5000).ToArray());   // truncated object: chunk 1 is short
        var m = Fixture.Manifest(data, pub, origin: origin.Url);
        using var oc = new XMesh.Transport.OriginClient();

        long before = PooledBuffer.Outstanding;
        var ex = await Assert.ThrowsAsync<XMeshException>(() => oc.GetChunkPooledAsync(m, 1, default));
        Assert.Equal(XMeshErrorCode.OriginUnavailable, ex.Code);
        Assert.Equal(before, PooledBuffer.Outstanding);
    }
}
