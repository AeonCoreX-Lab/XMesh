using System.Buffers;
using System.Security.Cryptography;
using XMesh.Core;

namespace XMesh.Assets;

public static class ManifestBuilder
{
    public const int DefaultChunkSize = 4 * 1024 * 1024; // spec section 16 example

    /// <summary>Stream a file once, hashing each chunk. Memory use is bounded by one chunk (pooled).</summary>
    public static async Task<AssetManifest> BuildAsync(
        string filePath, string assetId, string version, string publisher,
        string publisherKeyHex, string? origin = null, int chunkSize = DefaultChunkSize,
        CancellationToken ct = default)
    {
        if (chunkSize < AssetManifest.MinChunkSize || chunkSize > AssetManifest.MaxChunkSize)
            throw new ArgumentOutOfRangeException(nameof(chunkSize));

        var chunks = new List<string>();
        long total = 0;
        var buf = ArrayPool<byte>.Shared.Rent(chunkSize);
        try
        {
            await using var fs = new FileStream(filePath, new FileStreamOptions
            {
                Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                BufferSize = 0,
            });

            while (true)
            {
                int filled = 0;
                while (filled < chunkSize)
                {
                    int n = await fs.ReadAsync(buf.AsMemory(filled, chunkSize - filled), ct).ConfigureAwait(false);
                    if (n == 0) break;
                    filled += n;
                }
                if (filled == 0) break;
                chunks.Add(Convert.ToHexString(SHA256.HashData(buf.AsSpan(0, filled))).ToLowerInvariant());
                total += filled;
                if (filled < chunkSize) break;
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }

        var manifest = new AssetManifest
        {
            AssetId = assetId, Version = version, Size = total, ChunkSize = chunkSize,
            Chunks = chunks, Publisher = publisher, PublisherKey = publisherKeyHex, Origin = origin,
        };
        manifest.Validate();
        return manifest;
    }
}

public static class ChunkVerifier
{
    /// <summary>Constant-time comparison of a chunk against its manifest hash.</summary>
    public static bool Verify(AssetManifest manifest, int index, ReadOnlySpan<byte> data)
    {
        if ((uint)index >= (uint)manifest.ChunkCount) return false;
        if (data.Length != manifest.ChunkLength(index)) return false;
        Span<byte> actual = stackalloc byte[32];
        SHA256.HashData(data, actual);
        Span<byte> expected = stackalloc byte[32];
        Convert.FromHexString(manifest.Chunks[index], expected, out _, out _);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public static void VerifyOrThrow(AssetManifest manifest, int index, ReadOnlySpan<byte> data)
    {
        if (!Verify(manifest, index, data))
            throw new XMeshException(XMeshErrorCode.ChunkHashMismatch,
                $"Chunk {index} of {manifest.AssetId}@{manifest.Version} failed verification.");
    }
}
