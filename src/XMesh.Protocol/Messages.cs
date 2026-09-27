using System.Buffers.Binary;
using System.Text;
using XMesh.Core;

namespace XMesh.Protocol;

/// <summary>Protocol constants and capability negotiation (spec section 78).</summary>
public static class ProtocolInfo
{
    public const int Version = 1;
    public const int NonceLength = 32;
    public const int MaxStringLength = 1024;
}

/// <summary>Minimal big-endian reader that throws ProtocolViolation on any overrun instead of crashing.</summary>
public ref struct PayloadReader
{
    private ReadOnlySpan<byte> _s;
    public PayloadReader(ReadOnlySpan<byte> s) => _s = s;
    public readonly int Remaining => _s.Length;

    private void Need(int n)
    {
        if (n < 0 || _s.Length < n) throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Truncated message.");
    }

    public byte ReadByte() { Need(1); var v = _s[0]; _s = _s[1..]; return v; }
    public int ReadInt32() { Need(4); var v = BinaryPrimitives.ReadInt32BigEndian(_s); _s = _s[4..]; return v; }
    public uint ReadUInt32() { Need(4); var v = BinaryPrimitives.ReadUInt32BigEndian(_s); _s = _s[4..]; return v; }
    public long ReadInt64() { Need(8); var v = BinaryPrimitives.ReadInt64BigEndian(_s); _s = _s[8..]; return v; }

    public byte[] ReadBytes(int n) { Need(n); var v = _s[..n].ToArray(); _s = _s[n..]; return v; }

    public byte[] ReadLengthPrefixed(int max)
    {
        int n = ReadInt32();
        if (n < 0 || n > max) throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Bad field length.");
        return ReadBytes(n);
    }

    public string ReadString(int max = ProtocolInfo.MaxStringLength)
    {
        var b = ReadLengthPrefixed(max);
        try { return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(b); }
        catch (ArgumentException ex) { throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Invalid UTF-8.", ex); }
    }
}

public sealed class PayloadWriter
{
    private readonly MemoryStream _ms = new();
    public PayloadWriter WriteByte(byte v) { _ms.WriteByte(v); return this; }
    public PayloadWriter WriteInt32(int v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, v); _ms.Write(b); return this; }
    public PayloadWriter WriteInt64(long v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(b, v); _ms.Write(b); return this; }
    public PayloadWriter WriteBytes(ReadOnlySpan<byte> v) { _ms.Write(v); return this; }
    public PayloadWriter WriteLengthPrefixed(ReadOnlySpan<byte> v) { WriteInt32(v.Length); _ms.Write(v); return this; }
    public PayloadWriter WriteString(string s) => WriteLengthPrefixed(Encoding.UTF8.GetBytes(s));
    public byte[] ToArray() => _ms.ToArray();
}

/// <summary>Hello: protocol version, node's SPKI, and capability flags.</summary>
public sealed record HelloMessage(int ProtocolVersion, byte[] PublicKeySpki, bool CanServe)
{
    public byte[] Encode() => new PayloadWriter()
        .WriteInt32(ProtocolVersion).WriteLengthPrefixed(PublicKeySpki).WriteByte(CanServe ? (byte)1 : (byte)0).ToArray();

    public static HelloMessage Decode(ReadOnlySpan<byte> p)
    {
        var r = new PayloadReader(p);
        int v = r.ReadInt32();
        var key = r.ReadLengthPrefixed(256);
        byte f = r.ReadByte();
        if (r.Remaining != 0) throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Trailing bytes in Hello.");
        return new HelloMessage(v, key, f == 1);
    }
}

public sealed record GetChunkMessage(string AssetId, string Version, int Index)
{
    public byte[] Encode() => new PayloadWriter().WriteString(AssetId).WriteString(Version).WriteInt32(Index).ToArray();
    public static GetChunkMessage Decode(ReadOnlySpan<byte> p)
    {
        var r = new PayloadReader(p);
        var m = new GetChunkMessage(r.ReadString(256), r.ReadString(64), r.ReadInt32());
        if (r.Remaining != 0) throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Trailing bytes.");
        return m;
    }
}

public sealed record GetManifestMessage(string AssetId, string Version)
{
    public byte[] Encode() => new PayloadWriter().WriteString(AssetId).WriteString(Version).ToArray();
    public static GetManifestMessage Decode(ReadOnlySpan<byte> p)
    {
        var r = new PayloadReader(p);
        var m = new GetManifestMessage(r.ReadString(256), r.ReadString(64));
        if (r.Remaining != 0) throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Trailing bytes.");
        return m;
    }
}

/// <summary>Chunk response: index followed by raw bytes. The receiver hash-verifies against the manifest.</summary>
public sealed record ChunkMessage(int Index, byte[] Data)
{
    public byte[] Encode() => new PayloadWriter().WriteInt32(Index).WriteLengthPrefixed(Data).ToArray();
    public static ChunkMessage Decode(ReadOnlySpan<byte> p)
    {
        var r = new PayloadReader(p);
        int idx = r.ReadInt32();
        var data = r.ReadLengthPrefixed(Frame.MaxPayload);
        if (r.Remaining != 0) throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Trailing bytes.");
        return new ChunkMessage(idx, data);
    }
}

/// <summary>Allocation-free decode of a Chunk payload: (index, view of the data inside the payload).</summary>
public static class ChunkWire
{
    public static int Parse(ReadOnlySpan<byte> payload, out ReadOnlySpan<byte> data)
    {
        var r = new PayloadReader(payload);
        int index = r.ReadInt32();
        int len = r.ReadInt32();
        if (len < 0 || len > Frame.MaxPayload || len != r.Remaining)
            throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Bad chunk length.");
        data = payload.Slice(payload.Length - len, len);
        return index;
    }
}
