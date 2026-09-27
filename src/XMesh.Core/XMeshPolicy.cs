namespace XMesh.Core;

/// <summary>Resource limits (spec section 24). Defaults are deliberately restrictive (section 45).</summary>
public sealed record XMeshPolicy
{
    public int MaxConnections { get; init; } = 8;
    public int MaxConcurrentTransfers { get; init; } = 4;
    public long MaxCacheSizeBytes { get; init; } = 10L * 1024 * 1024 * 1024;
    /// <summary>Bandwidth cap applied to BOTH directions unless overridden below. 0 = unlimited.</summary>
    public long MaxBandwidthBytesPerSecond { get; init; } = 0;
    /// <summary>Cap on bytes this node sends to peers (serving). null = use <see cref="MaxBandwidthBytesPerSecond"/>.</summary>
    public long? MaxUploadBytesPerSecond { get; init; }
    /// <summary>Cap on bytes this node downloads (peers + origin combined). null = use <see cref="MaxBandwidthBytesPerSecond"/>.</summary>
    public long? MaxDownloadBytesPerSecond { get; init; }

    public long EffectiveUploadLimit => MaxUploadBytesPerSecond ?? MaxBandwidthBytesPerSecond;
    public long EffectiveDownloadLimit => MaxDownloadBytesPerSecond ?? MaxBandwidthBytesPerSecond;
    /// <summary>If false, this node never serves chunks to peers.</summary>
    public bool AllowServing { get; init; } = true;
    /// <summary>If true, only peers in the allowlist may connect (spec section 45: default restrictive).</summary>
    public bool RequireAllowlist { get; init; } = true;
    public TimeSpan PeerConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan ChunkTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public int MaxChunkRetries { get; init; } = 3;

    public void Validate()
    {
        if (MaxConnections < 1) throw new ArgumentOutOfRangeException(nameof(MaxConnections));
        if (MaxConcurrentTransfers < 1) throw new ArgumentOutOfRangeException(nameof(MaxConcurrentTransfers));
        if (MaxCacheSizeBytes < 0) throw new ArgumentOutOfRangeException(nameof(MaxCacheSizeBytes));
        if (MaxBandwidthBytesPerSecond < 0) throw new ArgumentOutOfRangeException(nameof(MaxBandwidthBytesPerSecond));
        if (MaxUploadBytesPerSecond < 0) throw new ArgumentOutOfRangeException(nameof(MaxUploadBytesPerSecond));
        if (MaxDownloadBytesPerSecond < 0) throw new ArgumentOutOfRangeException(nameof(MaxDownloadBytesPerSecond));
        if (MaxChunkRetries < 0) throw new ArgumentOutOfRangeException(nameof(MaxChunkRetries));
    }
}
