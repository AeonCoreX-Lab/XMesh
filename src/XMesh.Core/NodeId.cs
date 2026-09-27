using System.Security.Cryptography;

namespace XMesh.Core;

/// <summary>
/// Stable node identity (spec section 10). NodeId is derived from the public key,
/// so it is NOT a network address: Node Identity != Network Address.
/// </summary>
public readonly record struct NodeId
{
    public const int ByteLength = 32;
    private readonly byte[]? _bytes;

    public NodeId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"NodeId must be {ByteLength} bytes.", nameof(bytes));
        _bytes = bytes.ToArray();
    }

    public ReadOnlySpan<byte> Bytes => _bytes ?? new byte[ByteLength];

    /// <summary>NodeId = SHA-256(SubjectPublicKeyInfo DER of the node's public key).</summary>
    public static NodeId FromPublicKey(ReadOnlySpan<byte> spki) => new(SHA256.HashData(spki));

    public string ToHex() => Convert.ToHexString(Bytes).ToLowerInvariant();

    /// <summary>Short form for logs only. Never use for comparison.</summary>
    public string Short => ToHex()[..12];

    public static NodeId Parse(string hex) => new(Convert.FromHexString(hex));

    public bool Equals(NodeId other) => Bytes.SequenceEqual(other.Bytes);
    public override int GetHashCode()
    {
        var b = Bytes;
        return HashCode.Combine(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
    }
    public override string ToString() => ToHex();
}
