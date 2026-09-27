using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using XMesh.Core;
using XMesh.Protocol;
using XMesh.Security;

namespace XMesh.Transport;

/// <summary>An authenticated, encrypted connection to one remote node.</summary>
public sealed class PeerSession : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly TcpClient? _tcp;

    public NodeId RemoteId { get; }
    public byte[] RemoteSpki { get; }
    public bool RemoteCanServe { get; }

    internal PeerSession(Stream stream, TcpClient? tcp, NodeId id, byte[] spki, bool canServe)
    {
        _stream = stream; _tcp = tcp; RemoteId = id; RemoteSpki = spki; RemoteCanServe = canServe;
    }

    public async Task SendAsync(MessageType t, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try { await Frame.WriteAsync(_stream, t, payload, ct).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    /// <summary>Send a chunk without copying it into an intermediate message buffer.</summary>
    public async Task SendChunkAsync(int index, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try { await Frame.WriteChunkAsync(_stream, index, data, ct).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    /// <summary>Receive a frame into a pooled buffer that the caller owns and must dispose.</summary>
    public Task<(MessageType Type, PooledBuffer Payload)?> ReceivePooledAsync(CancellationToken ct, int maxPayload = Frame.MaxPayload) =>
        Frame.ReadPooledAsync(_stream, maxPayload, ct);

    public Task<(MessageType Type, byte[] Payload)?> ReceiveAsync(CancellationToken ct, int maxPayload = Frame.MaxPayload) =>
        Frame.ReadAsync(_stream, maxPayload, ct);

    public async ValueTask DisposeAsync()
    {
        // Best-effort courtesy notice, bounded: closing a connection must never make the caller wait on the
        // network. A busy or unresponsive peer (or a hedge-losing connection being torn down mid-transfer)
        // must not add latency to shutdown - measured to add ~800ms per disposal without this bound.
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            await SendAsync(MessageType.Bye, ReadOnlyMemory<byte>.Empty, cts.Token).ConfigureAwait(false);
        }
        catch { /* best effort */ }
        await _stream.DisposeAsync().ConfigureAwait(false);
        _tcp?.Dispose();
        _writeLock.Dispose();
    }

    // ---------------------------------------------------------------- handshake

    /// <summary>Client side: connect, TLS, then run the mutual identity handshake.</summary>
    public static async Task<PeerSession> ConnectAsync(string host, int port, NodeIdentity self,
        ITrustStore trust, XMeshPolicy policy, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
            to.CancelAfter(policy.PeerConnectTimeout);
            try { await tcp.ConnectAsync(host, port, to.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            { throw new XMeshException(XMeshErrorCode.PeerUnavailable, $"Timed out connecting to {host}:{port}."); }
            catch (SocketException ex)
            { throw new XMeshException(XMeshErrorCode.PeerUnavailable, $"Cannot connect to {host}:{port}: {ex.SocketErrorCode}.", ex); }

            var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false); // identity is verified by the XMA handshake, not by the cert
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "xma-node",
                EnabledSslProtocols = SslProtocols.Tls13,
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            }, to.Token).ConfigureAwait(false);

            return await DoHandshakeAsync(ssl, tcp, self, trust, policy, Handshake.Role.Initiator, to.Token).ConfigureAwait(false);
        }
        catch { tcp.Dispose(); throw; }
    }

    /// <summary>Server side: TLS accept, then run the mutual identity handshake.</summary>
    public static async Task<PeerSession> AcceptAsync(TcpClient tcp, X509Certificate2 cert, NodeIdentity self,
        ITrustStore trust, XMeshPolicy policy, CancellationToken ct)
    {
        try
        {
            tcp.NoDelay = true;
            using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
            to.CancelAfter(policy.PeerConnectTimeout);

            var ssl = new SslStream(tcp.GetStream(), false);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = cert,
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificateRequired = false,
            }, to.Token).ConfigureAwait(false);

            return await DoHandshakeAsync(ssl, tcp, self, trust, policy, Handshake.Role.Responder, to.Token).ConfigureAwait(false);
        }
        catch { tcp.Dispose(); throw; }
    }

    private static async Task<PeerSession> DoHandshakeAsync(Stream s, TcpClient tcp, NodeIdentity self,
        ITrustStore trust, XMeshPolicy policy, Handshake.Role role, CancellationToken ct)
    {
        const int MaxHandshakePayload = 4096;
        var myNonce = Handshake.NewNonce();
        var hello = new HelloMessage(ProtocolInfo.Version, self.PublicKeySpki, policy.AllowServing);

        // 1) Hello exchange (both sides send first; writes are small so this cannot deadlock).
        await Frame.WriteAsync(s, MessageType.Hello, hello.Encode(), ct).ConfigureAwait(false);
        var f = await Frame.ReadAsync(s, MaxHandshakePayload, ct).ConfigureAwait(false)
                ?? throw new XMeshException(XMeshErrorCode.HandshakeFailed, "Peer closed during Hello.");
        Expect(f.Type, MessageType.Hello);
        var remote = HelloMessage.Decode(f.Payload);
        if (remote.ProtocolVersion != ProtocolInfo.Version)
            throw new XMeshException(XMeshErrorCode.HandshakeFailed, $"Unsupported protocol version {remote.ProtocolVersion}.");

        // 2) Nonce exchange.
        await Frame.WriteAsync(s, MessageType.Challenge, myNonce, ct).ConfigureAwait(false);
        f = await Frame.ReadAsync(s, MaxHandshakePayload, ct).ConfigureAwait(false)
            ?? throw new XMeshException(XMeshErrorCode.HandshakeFailed, "Peer closed during Challenge.");
        Expect(f.Type, MessageType.Challenge);
        if (f.Payload.Length != Handshake.NonceLength)
            throw new XMeshException(XMeshErrorCode.HandshakeFailed, "Bad nonce length.");
        var theirNonce = f.Payload;

        var (initNonce, respNonce) = role == Handshake.Role.Initiator ? (myNonce, theirNonce) : (theirNonce, myNonce);
        var peerRole = role == Handshake.Role.Initiator ? Handshake.Role.Responder : Handshake.Role.Initiator;

        // 3) Prove possession of our key; verify theirs.
        var proof = Handshake.Prove(self, role, initNonce, respNonce, remote.PublicKeySpki);
        await Frame.WriteAsync(s, MessageType.Auth, proof, ct).ConfigureAwait(false);
        f = await Frame.ReadAsync(s, MaxHandshakePayload, ct).ConfigureAwait(false)
            ?? throw new XMeshException(XMeshErrorCode.HandshakeFailed, "Peer closed during Auth.");
        Expect(f.Type, MessageType.Auth);

        if (!Handshake.VerifyPeer(remote.PublicKeySpki, peerRole, initNonce, respNonce, self.PublicKeySpki, f.Payload))
            throw new XMeshException(XMeshErrorCode.HandshakeFailed, "Peer failed to prove key possession.");

        var remoteId = NodeId.FromPublicKey(remote.PublicKeySpki);
        if (remoteId.Equals(self.Id))
            throw new XMeshException(XMeshErrorCode.HandshakeFailed, "Refusing connection to self.");

        // 4) Authorization (allowlist) AFTER authentication. Each side decides independently whether it
        //    accepts the other, then tells the other side the verdict explicitly (AuthOk or Error), so a
        //    refusal is reported as "not authorized" instead of surfacing later as a broken pipe.
        string? refusal = null;
        try { Handshake.RequireAllowed(trust, remoteId, policy.RequireAllowlist); }
        catch (XMeshException ex) when (ex.Code == XMeshErrorCode.PeerRejected) { refusal = ex.Message; }

        if (refusal is null) await Frame.WriteAsync(s, MessageType.AuthOk, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
        else await Frame.WriteAsync(s, MessageType.Error, System.Text.Encoding.UTF8.GetBytes("not authorized"), ct).ConfigureAwait(false);

        f = await Frame.ReadAsync(s, MaxHandshakePayload, ct).ConfigureAwait(false)
            ?? throw new XMeshException(XMeshErrorCode.HandshakeFailed, "Peer closed before confirming authorization.");

        if (refusal is not null)
            throw new XMeshException(XMeshErrorCode.PeerRejected, refusal); // we refused them
        if (f.Type == MessageType.Error)
            throw new XMeshException(XMeshErrorCode.PeerRejected,
                $"Peer {remoteId.Short} refused this node: {System.Text.Encoding.UTF8.GetString(f.Payload)}. " +
                $"Ask its operator to run: xma trust peer {self.Id}");
        Expect(f.Type, MessageType.AuthOk);

        return new PeerSession(s, tcp, remoteId, remote.PublicKeySpki, remote.CanServe);
    }

    private static void Expect(MessageType actual, MessageType expected)
    {
        if (actual != expected)
            throw new XMeshException(XMeshErrorCode.HandshakeFailed, $"Expected {expected}, got {actual}.");
    }
}
