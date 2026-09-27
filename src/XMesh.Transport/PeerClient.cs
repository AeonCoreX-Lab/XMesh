using System.Text;
using XMesh.Assets;
using XMesh.Core;
using XMesh.Protocol;

namespace XMesh.Transport;

/// <summary>Fetches manifests and chunks from one authenticated peer.</summary>
public sealed class PeerClient
{
    private readonly PeerSession _session;
    public PeerClient(PeerSession session) => _session = session;
    public PeerSession Session => _session;

    public async Task<AssetManifest?> GetManifestAsync(string assetId, string version, CancellationToken ct)
    {
        await _session.SendAsync(MessageType.GetManifest, new GetManifestMessage(assetId, version).Encode(), ct).ConfigureAwait(false);
        var f = await _session.ReceiveAsync(ct, maxPayload: 4 * 1024 * 1024).ConfigureAwait(false)
                ?? throw new XMeshException(XMeshErrorCode.PeerUnavailable, "Peer closed connection.");
        return f.Type switch
        {
            MessageType.Manifest => AssetManifest.FromJson(Encoding.UTF8.GetString(f.Payload)),
            MessageType.NotFound => null,
            MessageType.Error => throw new XMeshException(XMeshErrorCode.PeerRejected, Encoding.UTF8.GetString(f.Payload)),
            _ => throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Unexpected {f.Type}."),
        };
    }


    /// <summary>
    /// Fetch one chunk into a pooled buffer. The CALLER owns the returned buffer and must dispose it
    /// (use <c>using</c>). Returns null when the peer does not have the chunk.
    /// Bytes are still UNVERIFIED here; the cache verifies against the manifest before persisting.
    /// </summary>
    public async Task<PooledBuffer?> GetChunkPooledAsync(string assetId, string version, int index, CancellationToken ct)
    {
        await _session.SendAsync(MessageType.GetChunk, new GetChunkMessage(assetId, version, index).Encode(), ct).ConfigureAwait(false);
        var f = await _session.ReceivePooledAsync(ct).ConfigureAwait(false)
                ?? throw new XMeshException(XMeshErrorCode.PeerUnavailable, "Peer closed connection.");
        var (type, payload) = f;
        try
        {
            switch (type)
            {
                case MessageType.Chunk:
                {
                    int got = ChunkWire.Parse(payload.Span, out var data);
                    if (got != index)
                        throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Peer returned wrong chunk index.");
                    var chunk = PooledBuffer.Rent(data.Length);          // copy only the data (drops the 8-byte prefix)
                    data.CopyTo(chunk.Span);
                    return chunk;
                }
                case MessageType.NotFound: return null;
                case MessageType.Error: throw new XMeshException(XMeshErrorCode.PeerRejected, Encoding.UTF8.GetString(payload.Span));
                default: throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Unexpected {type}.");
            }
        }
        finally { payload.Dispose(); }                                    // the frame buffer is always returned
    }

    /// <summary>
    /// Fetch one chunk. The bytes are returned UNVERIFIED-by-transport; the caller (cache) verifies
    /// against the manifest, so a lying peer can never poison the cache.
    /// </summary>
    public async Task<byte[]?> GetChunkAsync(string assetId, string version, int index, CancellationToken ct)
    {
        await _session.SendAsync(MessageType.GetChunk, new GetChunkMessage(assetId, version, index).Encode(), ct).ConfigureAwait(false);
        var f = await _session.ReceiveAsync(ct).ConfigureAwait(false)
                ?? throw new XMeshException(XMeshErrorCode.PeerUnavailable, "Peer closed connection.");
        switch (f.Type)
        {
            case MessageType.Chunk:
                var c = ChunkMessage.Decode(f.Payload);
                if (c.Index != index)
                    throw new XMeshException(XMeshErrorCode.ProtocolViolation, "Peer returned wrong chunk index.");
                return c.Data;
            case MessageType.NotFound: return null;
            case MessageType.Error: throw new XMeshException(XMeshErrorCode.PeerRejected, Encoding.UTF8.GetString(f.Payload));
            default: throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Unexpected {f.Type}.");
        }
    }
}
