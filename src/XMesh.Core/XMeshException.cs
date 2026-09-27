namespace XMesh.Core;

/// <summary>Machine-readable failure categories (spec section 38: failures are normal).</summary>
public enum XMeshErrorCode
{
    Unknown = 0,
    AssetNotFound,
    ManifestInvalid,
    ManifestSignatureInvalid,
    ChunkHashMismatch,
    PeerUnavailable,
    PeerRejected,
    HandshakeFailed,
    ProtocolViolation,
    OriginUnavailable,
    Cancelled,
    InsufficientDisk,
    PolicyDenied,
}

public class XMeshException : Exception
{
    public XMeshErrorCode Code { get; }

    public XMeshException(XMeshErrorCode code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;
}
