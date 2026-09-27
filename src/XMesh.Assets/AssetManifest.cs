using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using XMesh.Core;

namespace XMesh.Assets;

/// <summary>
/// Versioned asset manifest (spec section 16). The signature covers the canonical
/// signing bytes; a valid chunk hash alone proves nothing about publisher authenticity.
/// </summary>
public sealed class AssetManifest
{
    public const int CurrentFormat = 1;
    public const int MinChunkSize = 4 * 1024;
    public const int MaxChunkSize = 16 * 1024 * 1024;
    public const int MaxChunks = 1_000_000;

    [JsonPropertyName("format")] public int Format { get; init; } = CurrentFormat;
    [JsonPropertyName("assetId")] public required string AssetId { get; init; }
    [JsonPropertyName("version")] public required string Version { get; init; }
    [JsonPropertyName("size")] public required long Size { get; init; }
    [JsonPropertyName("chunkSize")] public required int ChunkSize { get; init; }
    /// <summary>Lowercase hex SHA-256 of each chunk, in order.</summary>
    [JsonPropertyName("chunks")] public required List<string> Chunks { get; init; }
    [JsonPropertyName("publisher")] public required string Publisher { get; init; }
    /// <summary>Hex SubjectPublicKeyInfo of the publisher's signing key.</summary>
    [JsonPropertyName("publisherKey")] public required string PublisherKey { get; init; }
    /// <summary>Optional HTTP(S) origin URL for fallback (spec section 40).</summary>
    [JsonPropertyName("origin")] public string? Origin { get; init; }
    /// <summary>Hex ECDSA-P256 signature over <see cref="GetSigningBytes"/>.</summary>
    [JsonPropertyName("signature")] public string? Signature { get; init; }

    [JsonIgnore] public int ChunkCount => Chunks.Count;

    /// <summary>Content identity: SHA-256 over the concatenated raw chunk digests.</summary>
    public string ComputeRoot()
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var c in Chunks) h.AppendData(Convert.FromHexString(c));
        return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant();
    }

    public int ChunkLength(int index)
    {
        if ((uint)index >= (uint)ChunkCount) throw new ArgumentOutOfRangeException(nameof(index));
        if (index < ChunkCount - 1) return ChunkSize;
        return checked((int)(Size - (long)ChunkSize * (ChunkCount - 1)));
    }

    /// <summary>Structural validation. Throws <see cref="XMeshException"/> on any inconsistency.</summary>
    public void Validate()
    {
        if (Format != CurrentFormat) Fail($"Unsupported manifest format {Format}.");
        if (string.IsNullOrWhiteSpace(AssetId) || AssetId.Length > 256) Fail("Invalid assetId.");
        if (!IsSafeToken(AssetId)) Fail("assetId contains illegal characters.");
        if (string.IsNullOrWhiteSpace(Version) || Version.Length > 64 || !IsSafeToken(Version)) Fail("Invalid version.");
        if (Size < 0) Fail("Negative size.");
        if (ChunkSize < MinChunkSize || ChunkSize > MaxChunkSize) Fail("chunkSize out of range.");
        if (Chunks is null) Fail("chunks missing.");
        if (Chunks!.Count > MaxChunks) Fail("Too many chunks.");

        long expected = Size == 0 ? 0 : (Size + ChunkSize - 1) / ChunkSize;
        if (Chunks.Count != expected) Fail($"Chunk count {Chunks.Count} does not match size (expected {expected}).");

        foreach (var c in Chunks)
            if (c is null || c.Length != 64 || !IsLowerHex(c)) Fail("Malformed chunk hash.");

        if (string.IsNullOrWhiteSpace(Publisher) || Publisher.Length > 128) Fail("Invalid publisher.");
        if (string.IsNullOrWhiteSpace(PublisherKey) || PublisherKey.Length > 512 || !IsLowerHex(PublisherKey)) Fail("Invalid publisherKey.");
        if (Origin is not null && !IsAllowedOrigin(Origin)) Fail("Origin must be an absolute http(s) URL.");
    }

    /// <summary>
    /// Canonical, deterministic bytes that the publisher signs. Length-prefixed fields
    /// so no two distinct manifests can share signing bytes (no delimiter ambiguity).
    /// </summary>
    public byte[] GetSigningBytes()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);
        w.Write(Encoding.ASCII.GetBytes("XMA-MANIFEST-V1"));
        WriteStr(w, AssetId);
        WriteStr(w, Version);
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(Size));
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(ChunkSize));
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(Chunks.Count));
        foreach (var c in Chunks) w.Write(Convert.FromHexString(c));
        WriteStr(w, Publisher);
        WriteStr(w, PublisherKey);
        WriteStr(w, Origin ?? string.Empty);
        w.Flush();
        return ms.ToArray();
    }

    public string ToJson() => JsonSerializer.Serialize(this, ManifestJson.Options);

    public static AssetManifest FromJson(string json)
    {
        AssetManifest? m;
        try { m = JsonSerializer.Deserialize<AssetManifest>(json, ManifestJson.Options); }
        catch (JsonException ex) { throw new XMeshException(XMeshErrorCode.ManifestInvalid, "Manifest JSON is malformed.", ex); }
        if (m is null) throw new XMeshException(XMeshErrorCode.ManifestInvalid, "Manifest is empty.");
        m.Validate();
        return m;
    }

    public AssetManifest WithSignature(string signatureHex) => new()
    {
        Format = Format, AssetId = AssetId, Version = Version, Size = Size, ChunkSize = ChunkSize,
        Chunks = Chunks, Publisher = Publisher, PublisherKey = PublisherKey, Origin = Origin,
        Signature = signatureHex,
    };

    private static void WriteStr(BinaryWriter w, string s)
    {
        var b = Encoding.UTF8.GetBytes(s);
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(b.Length));
        w.Write(b);
    }

    private static void Fail(string msg) => throw new XMeshException(XMeshErrorCode.ManifestInvalid, msg);

    /// <summary>assetId/version become path components in the cache, so reject anything path-like.</summary>
    public static bool IsSafeToken(string s)
    {
        foreach (var ch in s)
        {
            bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
                      || ch == '-' || ch == '_' || ch == '.';
            if (!ok) return false;
        }
        return s != "." && s != ".." && !s.StartsWith('.');
    }

    private static bool IsLowerHex(string s)
    {
        if (s.Length % 2 != 0) return false;
        foreach (var ch in s)
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
        return true;
    }

    private static bool IsAllowedOrigin(string s) =>
        Uri.TryCreate(s, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps);
}

internal static class ManifestJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
}
