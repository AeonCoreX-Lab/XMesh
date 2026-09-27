using XMesh.Core;

namespace XMesh.Runtime;

/// <summary>Result of a completed request (spec section 62).</summary>
public sealed record AssetResult(
    string AssetId,
    string Version,
    long Size,
    string LocalPath,
    bool Verified,
    long BytesFromCache,
    long BytesFromPeers,
    long BytesFromOrigin,
    TimeSpan Elapsed)
{
    public bool ServedEntirelyFromCache => BytesFromPeers == 0 && BytesFromOrigin == 0;
}

public sealed record AssetRequest(string AssetId, string Version)
{
    /// <summary>If set, the manifest is fetched from this file/URL rather than from peers.</summary>
    public string? ManifestPath { get; init; }
    public bool AllowPeers { get; init; } = true;
    public bool AllowOrigin { get; init; } = true;
}
