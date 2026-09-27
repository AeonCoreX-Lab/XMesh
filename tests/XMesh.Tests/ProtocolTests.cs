using XMesh.Core;
using XMesh.Protocol;
using Xunit;

namespace XMesh.Tests;

public class FrameTests
{
    [Fact]
    public async Task Roundtrip_over_a_stream()
    {
        var ms = new MemoryStream();
        await Frame.WriteAsync(ms, MessageType.GetChunk, new GetChunkMessage("a", "1", 7).Encode(), default);
        ms.Position = 0;
        var f = await Frame.ReadAsync(ms, Frame.MaxPayload, default);
        Assert.NotNull(f);
        Assert.Equal(MessageType.GetChunk, f!.Value.Type);
        var m = GetChunkMessage.Decode(f.Value.Payload);
        Assert.Equal(("a", "1", 7), (m.AssetId, m.Version, m.Index));
    }

    [Fact]
    public async Task Clean_eof_at_boundary_returns_null()
    {
        Assert.Null(await Frame.ReadAsync(new MemoryStream(), Frame.MaxPayload, default));
    }

    [Fact]
    public async Task Bad_magic_is_a_protocol_violation()
    {
        var bad = new byte[] { (byte)'N', (byte)'O', (byte)'P', (byte)'E', 1, 0, 0, 0, 0 };
        var ex = await Assert.ThrowsAsync<XMeshException>(() => Frame.ReadAsync(new MemoryStream(bad), Frame.MaxPayload, default));
        Assert.Equal(XMeshErrorCode.ProtocolViolation, ex.Code);
    }

    [Fact]
    public async Task Oversized_length_is_rejected_before_allocating()
    {
        var hdr = Frame.Encode(MessageType.Chunk, Array.Empty<byte>());
        hdr[5] = 0x7F; hdr[6] = 0xFF; hdr[7] = 0xFF; hdr[8] = 0xFF; // claims ~2 GiB
        var ex = await Assert.ThrowsAsync<XMeshException>(() => Frame.ReadAsync(new MemoryStream(hdr), Frame.MaxPayload, default));
        Assert.Equal(XMeshErrorCode.ProtocolViolation, ex.Code);
    }

    [Fact]
    public async Task Per_call_limit_is_enforced_below_global_limit()
    {
        var f = Frame.Encode(MessageType.Chunk, new byte[5000]);
        await Assert.ThrowsAsync<XMeshException>(() => Frame.ReadAsync(new MemoryStream(f), 4096, default));
    }

    [Fact]
    public async Task Unknown_message_type_is_rejected()
    {
        var f = Frame.Encode(MessageType.Hello, Array.Empty<byte>());
        f[4] = 200;
        await Assert.ThrowsAsync<XMeshException>(() => Frame.ReadAsync(new MemoryStream(f), Frame.MaxPayload, default));
    }

    [Fact]
    public async Task Truncated_payload_throws_rather_than_hanging_or_returning_partial_data()
    {
        var f = Frame.Encode(MessageType.Chunk, new byte[100]);
        var cut = f[..^10];
        await Assert.ThrowsAnyAsync<Exception>(() => Frame.ReadAsync(new MemoryStream(cut), Frame.MaxPayload, default));
    }

    [Fact]
    public void Message_decoders_reject_truncated_and_trailing_bytes()
    {
        var good = new GetChunkMessage("asset", "1", 3).Encode();
        Assert.Throws<XMeshException>(() => GetChunkMessage.Decode(good.AsSpan(0, good.Length - 1)));
        Assert.Throws<XMeshException>(() => GetChunkMessage.Decode(good.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Negative_or_huge_field_lengths_are_rejected()
    {
        var neg = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };
        Assert.Throws<XMeshException>(() => { var r = new PayloadReader(neg); r.ReadString(); });
        var huge = new byte[] { 0x7F, 0xFF, 0xFF, 0xFF, 1, 2, 3 };
        Assert.Throws<XMeshException>(() => { var r = new PayloadReader(huge); r.ReadString(); });
    }

    [Fact]
    public void Invalid_utf8_is_rejected()
    {
        var p = new PayloadWriter().WriteLengthPrefixed(new byte[] { 0xC3, 0x28 }).ToArray();
        Assert.Throws<XMeshException>(() => { var r = new PayloadReader(p); r.ReadString(); });
    }

    [Fact]
    public void Hello_roundtrips()
    {
        var h = new HelloMessage(1, new byte[] { 1, 2, 3 }, true);
        var d = HelloMessage.Decode(h.Encode());
        Assert.Equal(1, d.ProtocolVersion);
        Assert.Equal(new byte[] { 1, 2, 3 }, d.PublicKeySpki);
        Assert.True(d.CanServe);
    }
}

public class ZeroCopyChunkTests
{
    private static async Task<byte[]> ViaZeroCopy(int index, byte[] data)
    {
        var ms = new MemoryStream();
        await Frame.WriteChunkAsync(ms, index, data, default);
        return ms.ToArray();
    }

    private static byte[] ViaOriginalPath(int index, byte[] data) =>
        Frame.Encode(MessageType.Chunk, new ChunkMessage(index, data).Encode());

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(7, 4096)]
    [InlineData(123456, 100000)]
    public async Task Zero_copy_bytes_are_identical_to_the_original_encoding(int index, int size)
    {
        var data = new byte[size];
        new Random(index + size).NextBytes(data);
        Assert.Equal(ViaOriginalPath(index, data), await ViaZeroCopy(index, data));
    }

    [Fact]
    public async Task Zero_copy_output_decodes_with_the_normal_reader()
    {
        var data = new byte[70000];
        new Random(3).NextBytes(data);
        var wire = await ViaZeroCopy(9, data);
        var f = await Frame.ReadAsync(new MemoryStream(wire), Frame.MaxPayload, default);
        Assert.Equal(MessageType.Chunk, f!.Value.Type);
        var c = ChunkMessage.Decode(f.Value.Payload);
        Assert.Equal(9, c.Index);
        Assert.Equal(data, c.Data);
    }

    [Fact]
    public async Task Zero_copy_rejects_oversized_payloads_before_writing_anything()
    {
        var ms = new MemoryStream();
        var tooBig = new byte[Frame.MaxPayload];                 // payload = 8 + MaxPayload > MaxPayload
        await Assert.ThrowsAsync<XMeshException>(() => Frame.WriteChunkAsync(ms, 0, tooBig, default));
        Assert.Equal(0L, ms.Length);
    }

    [Fact]
    public async Task Zero_copy_accepts_the_largest_legal_chunk()
    {
        var ms = new MemoryStream();
        var max = new byte[16 * 1024 * 1024];                    // AssetManifest.MaxChunkSize
        await Frame.WriteChunkAsync(ms, 0, max, default);
        Assert.Equal(Frame.HeaderSize + 8 + max.Length, (int)ms.Length);
    }
}
