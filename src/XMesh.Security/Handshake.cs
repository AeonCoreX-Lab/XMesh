using System.Security.Cryptography;
using XMesh.Core;

namespace XMesh.Security;

/// <summary>
/// Mutual challenge-response authentication (spec section 20: Identity -> Authentication).
///
/// Both sides pick a fresh random nonce and send it. Each side then signs
///     "XMA-AUTH-V1" || role || nonceA || nonceB || signerSpki || peerSpki
/// with its long-lived identity key. Binding BOTH nonces, BOTH keys and the role into the signed
/// bytes means a signature cannot be replayed in another session, reflected back to its author,
/// or reused with a different peer.
///
/// NOTE (honest scope): this proves key possession and authenticates the peer. It does NOT by
/// itself encrypt the stream. Phase 1 transport confidentiality is provided by TLS in
/// SecureChannel; this handshake is the application-layer identity proof on top of it.
/// </summary>
public static class Handshake
{
    public const int NonceLength = 32;
    private static readonly byte[] Label = "XMA-AUTH-V1"u8.ToArray();

    public enum Role : byte { Initiator = 1, Responder = 2 }

    public static byte[] NewNonce() => RandomNumberGenerator.GetBytes(NonceLength);

    public static byte[] BuildSignedData(Role signerRole, ReadOnlySpan<byte> initiatorNonce,
        ReadOnlySpan<byte> responderNonce, ReadOnlySpan<byte> signerSpki, ReadOnlySpan<byte> peerSpki)
    {
        using var ms = new MemoryStream();
        ms.Write(Label);
        ms.WriteByte((byte)signerRole);
        ms.Write(initiatorNonce);
        ms.Write(responderNonce);
        WriteLp(ms, signerSpki);
        WriteLp(ms, peerSpki);
        return ms.ToArray();
    }

    /// <summary>Produce this node's proof of key possession for the session.</summary>
    public static byte[] Prove(NodeIdentity self, Role selfRole, ReadOnlySpan<byte> initiatorNonce,
        ReadOnlySpan<byte> responderNonce, ReadOnlySpan<byte> peerSpki)
    {
        var data = BuildSignedData(selfRole, initiatorNonce, responderNonce, self.PublicKeySpki, peerSpki);
        return self.Sign(data);
    }

    /// <summary>Verify the remote's proof. The remote's role is the opposite of ours.</summary>
    public static bool VerifyPeer(ReadOnlySpan<byte> peerSpki, Role peerRole, ReadOnlySpan<byte> initiatorNonce,
        ReadOnlySpan<byte> responderNonce, ReadOnlySpan<byte> selfSpki, ReadOnlySpan<byte> signature)
    {
        var data = BuildSignedData(peerRole, initiatorNonce, responderNonce, peerSpki, selfSpki);
        return NodeIdentity.Verify(peerSpki, data, signature);
    }

    /// <summary>Authorization gate applied AFTER authentication succeeds (allowlist).</summary>
    public static void RequireAllowed(ITrustStore trust, NodeId peer, bool requireAllowlist)
    {
        if (requireAllowlist && !trust.IsAllowedPeer(peer))
            throw new XMeshException(XMeshErrorCode.PeerRejected, $"Peer {peer.Short} is not in the allowlist.");
    }

    private static void WriteLp(Stream s, ReadOnlySpan<byte> v)
    {
        Span<byte> len = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(len, v.Length);
        s.Write(len);
        s.Write(v);
    }
}
