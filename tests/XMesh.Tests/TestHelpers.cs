using System.Security.Cryptography;
using XMesh.Assets;
using XMesh.Security;

namespace XMesh.Tests;

internal sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "xma-test-" + Guid.NewGuid().ToString("N"));
    public TempDir() => Directory.CreateDirectory(Path);
    public string Sub(string name) { var p = System.IO.Path.Combine(Path, name); Directory.CreateDirectory(p); return p; }
    public void Dispose() { try { Directory.Delete(Path, true); } catch { } }
}

internal static class Fixture
{
    public static byte[] RandomBytes(int n, int seed = 7)
    {
        var b = new byte[n];
        new Random(seed).NextBytes(b);
        return b;
    }

    /// <summary>Build and sign a manifest for in-memory data.</summary>
    public static AssetManifest Manifest(byte[] data, NodeIdentity publisher, string id = "asset-1", string ver = "1.0",
        int chunkSize = 4096, string? origin = null)
    {
        var chunks = new List<string>();
        for (int i = 0; i < data.Length; i += chunkSize)
            chunks.Add(Convert.ToHexString(SHA256.HashData(data.AsSpan(i, Math.Min(chunkSize, data.Length - i)))).ToLowerInvariant());
        var m = new AssetManifest
        {
            AssetId = id, Version = ver, Size = data.Length, ChunkSize = chunkSize, Chunks = chunks,
            Publisher = "test", PublisherKey = Convert.ToHexString(publisher.PublicKeySpki).ToLowerInvariant(), Origin = origin,
        };
        return ManifestSigner.Sign(m, publisher);
    }

    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}
