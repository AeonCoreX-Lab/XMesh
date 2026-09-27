using System.Security.Cryptography;
using XMesh.Security;
using XMesh.Assets;
using XMesh.Protocol;
using Xunit;

namespace XMesh.Tests;

/// <summary>
/// Cross-checks against vectors produced by an INDEPENDENT reference implementation
/// (xma-ref/wire_ref.py). If C# and the reference disagree, the wire format is not what we claim.
/// </summary>
public class WireVectorTests
{
    [Fact]
    public void Frame_matches_reference_bytes()
    {
        var f = Frame.Encode(MessageType.Auth, "hello"u8);
        Assert.Equal("584d4131030000000568656c6c6f", Convert.ToHexString(f).ToLowerInvariant());
    }

    [Fact]
    public void Chunk_hashes_and_root_match_reference()
    {
        var data = new byte[256000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 256);
        var m = new AssetManifest
        {
            AssetId = "vec", Version = "1", Size = data.Length, ChunkSize = 65536,
            Chunks = Enumerable.Range(0, 4).Select(i =>
                Convert.ToHexString(SHA256.HashData(data.AsSpan(i * 65536, Math.Min(65536, data.Length - i * 65536)))).ToLowerInvariant()).ToList(),
            Publisher = "p", PublisherKey = "aa",
        };
        Assert.Equal(4, m.ChunkCount);
        Assert.Equal(59392, m.ChunkLength(3));
        Assert.Equal("1d88e8dd6b05c25249c30b96467fbb73839509774501e7a9e97b7e0e694a70ba", m.ComputeRoot());
    }

    [Fact]
    public void Manifest_signing_bytes_match_reference_layout()
    {
        var data = new byte[5120];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 256);
        var m = new AssetManifest
        {
            AssetId = "vec-asset", Version = "1.0", Size = data.Length, ChunkSize = 4096,
            Chunks = new[] { 0, 4096 }.Select(o =>
                Convert.ToHexString(SHA256.HashData(data.AsSpan(o, Math.Min(4096, data.Length - o)))).ToLowerInvariant()).ToList(),
            Publisher = "pub", PublisherKey = new string('a', 1) + "b" + string.Concat(Enumerable.Repeat("ab", 19)) ,
        };
        // Reference used publisherKey = "ab" * 20 (40 chars): rebuild exactly that.
        var m2 = new AssetManifest
        {
            AssetId = m.AssetId, Version = m.Version, Size = m.Size, ChunkSize = m.ChunkSize, Chunks = m.Chunks,
            Publisher = "pub", PublisherKey = string.Concat(Enumerable.Repeat("ab", 20)),
        };
        var bytes = m2.GetSigningBytes();
        Assert.Equal(170, bytes.Length);
        Assert.Equal("5a5a869c459b2cad7f55542d60f4e1e68fdab6b9a2d6f2c18b2a96c19a63fa1b",
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
    }

    [Fact]
    public void Handshake_signed_data_matches_reference_layout()
    {
        var n1 = Enumerable.Repeat((byte)1, 32).ToArray();
        var n2 = Enumerable.Repeat((byte)2, 32).ToArray();
        var data = Handshake.BuildSignedData(Handshake.Role.Initiator, n1, n2,
            Enumerable.Repeat((byte)0xAA, 8).ToArray(), Enumerable.Repeat((byte)0xBB, 8).ToArray());
        Assert.Equal(100, data.Length);
        Assert.Equal("277b3a82e385b65b5fd3caf4dfb0a3c0d0183db52526afd739b22c48da1aa0aa",
            Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant());
    }
}
