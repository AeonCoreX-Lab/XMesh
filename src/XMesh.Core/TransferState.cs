namespace XMesh.Core;

/// <summary>Lifecycle states from spec section 62.</summary>
public enum TransferState
{
    Queued,
    Resolving,
    CheckingCache,
    DiscoveringPeers,
    Authenticating,
    Connecting,
    Transferring,
    Verifying,
    Caching,
    Completed,
    Failed,
    Cancelled,
}

public enum AssetSource { Cache, Peer, Origin }

public sealed record TransferProgress(
    string AssetId,
    TransferState State,
    long BytesDone,
    long BytesTotal,
    int ChunksDone,
    int ChunksTotal,
    AssetSource? CurrentSource);
