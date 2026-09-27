using System.Buffers;
using System.Buffers.Binary;
using XMesh.Core;

namespace XMesh.Protocol;

public enum MessageType : byte
{
    Hello = 1,        // capability + identity announcement
    Challenge = 2,    // handshake nonce
    Auth = 3,         // signed response proving key possession
    AuthOk = 4,
    GetManifest = 5,
    Manifest = 6,
    Have = 7,         // which chunks a peer holds
    GetChunk = 8,
    Chunk = 9,
    NotFound = 10,
    Error = 11,
    Bye = 12,
}

/// <summary>
/// Wire frame: [magic "XMA1" 4][type 1][length u32 big-endian 4][payload].
/// Length is bounded BEFORE allocation so a malicious peer cannot force a huge allocation.
/// </summary>
public static class Frame
{
    public static ReadOnlySpan<byte> Magic => "XMA1"u8;
    public const int HeaderSize = 9;
    /// <summary>Hard ceiling: max chunk (16 MiB) + per-message overhead.</summary>
    public const int MaxPayload = 16 * 1024 * 1024 + 4096;

    public static byte[] Encode(MessageType type, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaxPayload)
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Payload too large.");
        var buf = new byte[HeaderSize + payload.Length];
        Magic.CopyTo(buf);
        buf[4] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(5, 4), (uint)payload.Length);
        payload.CopyTo(buf.AsSpan(HeaderSize));
        return buf;
    }

    public static async Task WriteAsync(Stream s, MessageType type, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        if (payload.Length > MaxPayload)
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Payload too large.");
        var header = new byte[HeaderSize];
        Magic.CopyTo(header);
        header[4] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(5, 4), (uint)payload.Length);
        await s.WriteAsync(header, ct).ConfigureAwait(false);
        if (payload.Length > 0) await s.WriteAsync(payload, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }


    /// <summary>
    /// Send a Chunk frame with NO intermediate copy of the data.
    /// Wire layout is identical to <c>Encode(Chunk, new ChunkMessage(index, data).Encode())</c>:
    ///   header(9) | index i32 | dataLength i32 | data
    /// The small fixed prefix is one tiny buffer; the (possibly multi-MiB) data is written straight from the caller's memory.
    /// </summary>
    public static async Task WriteChunkAsync(Stream s, int index, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        const int Prefix = HeaderSize + 4 + 4;
        long payloadLen = 4L + 4L + data.Length;
        if (payloadLen > MaxPayload)
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Payload too large.");

        var head = new byte[Prefix];                       // 17 bytes: negligible, never on the LOH
        Magic.CopyTo(head);
        head[4] = (byte)MessageType.Chunk;
        BinaryPrimitives.WriteUInt32BigEndian(head.AsSpan(5, 4), (uint)payloadLen);
        BinaryPrimitives.WriteInt32BigEndian(head.AsSpan(9, 4), index);
        BinaryPrimitives.WriteInt32BigEndian(head.AsSpan(13, 4), data.Length);
        await s.WriteAsync(head, ct).ConfigureAwait(false);
        if (data.Length > 0) await s.WriteAsync(data, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }


    /// <summary>
    /// Like <see cref="ReadAsync"/> but the payload lives in a pooled buffer the CALLER owns and must dispose.
    /// Use for large frames (chunks) so receiving a multi-MiB chunk does not allocate a multi-MiB array.
    /// The same validation applies: the length is bounded before any allocation.
    /// </summary>
    public static async Task<(MessageType Type, PooledBuffer Payload)?> ReadPooledAsync(Stream s, int maxPayload, CancellationToken ct)
    {
        var header = new byte[HeaderSize];
        int got = 0;
        while (got < HeaderSize)
        {
            int n = await s.ReadAsync(header.AsMemory(got), ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (got == 0) return null;
                throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Connection closed mid-header.");
            }
            got += n;
        }
        if (!header.AsSpan(0, 4).SequenceEqual(Magic))
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Bad magic.");
        var type = (MessageType)header[4];
        if (!Enum.IsDefined(type))
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Unknown message type {header[4]}.");
        uint len = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(5, 4));
        if (len > (uint)Math.Min(maxPayload, MaxPayload))
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Frame length {len} exceeds limit.");

        var buf = PooledBuffer.Rent((int)len);
        try
        {
            await s.ReadExactlyAsync(buf.Memory, ct).ConfigureAwait(false);
            return (type, buf);
        }
        catch { buf.Dispose(); throw; }          // never leak a rented buffer on a truncated/cancelled read
    }

    /// <summary>Read one frame. Returns null on clean EOF at a frame boundary.</summary>
    public static async Task<(MessageType Type, byte[] Payload)?> ReadAsync(Stream s, int maxPayload, CancellationToken ct)
    {
        var header = new byte[HeaderSize];
        int got = 0;
        while (got < HeaderSize)
        {
            int n = await s.ReadAsync(header.AsMemory(got), ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (got == 0) return null;
                throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Connection closed mid-header.");
            }
            got += n;
        }

        if (!header.AsSpan(0, 4).SequenceEqual(Magic))
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Bad magic.");

        var type = (MessageType)header[4];
        if (!Enum.IsDefined(type))
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Unknown message type {header[4]}.");

        uint len = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(5, 4));
        if (len > (uint)Math.Min(maxPayload, MaxPayload))
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Frame length {len} exceeds limit.");

        var payload = new byte[len];
        await s.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
        return (type, payload);
    }
}
