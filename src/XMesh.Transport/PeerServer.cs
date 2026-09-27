using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using XMesh.Assets;
using XMesh.Cache;
using XMesh.Core;
using XMesh.Protocol;
using XMesh.Security;

namespace XMesh.Transport;

/// <summary>
/// Serves verified chunks from the local cache to authorized peers.
/// Never exposes arbitrary files (spec section 45): only assets in the cache, only complete
/// or verified chunks, and only when policy allows serving.
/// </summary>
public sealed class PeerServer : IAsyncDisposable
{
    private readonly AssetCache _cache;
    private readonly NodeIdentity _self;
    private readonly ITrustStore _trust;
    private readonly XMeshPolicy _policy;
    private readonly X509Certificate2 _cert;
    private readonly TcpListener _listener;
    private readonly SemaphoreSlim _slots;
    private readonly RateLimiter _upload;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _tasks = new();
    private readonly object _tasksLock = new();
    private Task? _acceptLoop;

    public int Port { get; private set; }
    public event Action<string>? Log;

    public PeerServer(AssetCache cache, NodeIdentity self, ITrustStore trust, XMeshPolicy policy, IPAddress? bind = null, int port = 0)
    {
        policy.Validate();
        _cache = cache; _self = self; _trust = trust; _policy = policy;
        _cert = TlsCertificate.CreateEphemeral();
        _slots = new SemaphoreSlim(policy.MaxConnections, policy.MaxConnections);
        _upload = new RateLimiter(policy.EffectiveUploadLimit);
        _listener = new TcpListener(bind ?? IPAddress.Any, port);
    }

    public void Start()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { continue; }

            // Enforce the connection cap: over-limit connections are dropped immediately.
            if (!_slots.Wait(0)) { client.Dispose(); continue; }

            var t = Task.Run(async () =>
            {
                try { await HandleAsync(client, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { }
                catch (XMeshException ex) { Log?.Invoke($"peer rejected: {ex.Code}: {ex.Message}"); }
                catch (IOException) { }
                catch (Exception ex) { Log?.Invoke($"peer error: {ex.GetType().Name}: {ex.Message}"); }
                finally { _slots.Release(); }
            }, ct);

            lock (_tasksLock) { _tasks.RemoveAll(x => x.IsCompleted); _tasks.Add(t); }
        }
    }

    private async Task HandleAsync(TcpClient tcp, CancellationToken ct)
    {
        await using var session = await PeerSession.AcceptAsync(tcp, _cert, _self, _trust, _policy, ct).ConfigureAwait(false);
        Log?.Invoke($"peer connected: {session.RemoteId.Short}");

        if (!_policy.AllowServing)
        {
            await session.SendAsync(MessageType.Error, "serving disabled"u8.ToArray(), ct).ConfigureAwait(false);
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
            idle.CancelAfter(TimeSpan.FromMinutes(2));
            (MessageType Type, byte[] Payload)? f;
            try { f = await session.ReceiveAsync(idle.Token, maxPayload: 4096).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return; } // idle timeout
            if (f is null || f.Value.Type == MessageType.Bye) return;

            switch (f.Value.Type)
            {
                case MessageType.GetManifest:
                    await ServeManifestAsync(session, GetManifestMessage.Decode(f.Value.Payload), ct).ConfigureAwait(false);
                    break;
                case MessageType.GetChunk:
                    await ServeChunkAsync(session, GetChunkMessage.Decode(f.Value.Payload), ct).ConfigureAwait(false);
                    break;
                default:
                    throw new XMeshException(XMeshErrorCode.ProtocolViolation, $"Unexpected message {f.Value.Type}.");
            }
        }
    }

    private async Task ServeManifestAsync(PeerSession s, GetManifestMessage req, CancellationToken ct)
    {
        if (!AssetManifest.IsSafeToken(req.AssetId) || !AssetManifest.IsSafeToken(req.Version))
        { await s.SendAsync(MessageType.NotFound, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false); return; }

        var m = _cache.TryLoadManifest(req.AssetId, req.Version);
        if (m is null) { await s.SendAsync(MessageType.NotFound, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false); return; }
        await s.SendAsync(MessageType.Manifest, System.Text.Encoding.UTF8.GetBytes(m.ToJson()), ct).ConfigureAwait(false);
    }

    private async Task ServeChunkAsync(PeerSession s, GetChunkMessage req, CancellationToken ct)
    {
        if (!AssetManifest.IsSafeToken(req.AssetId) || !AssetManifest.IsSafeToken(req.Version))
        { await s.SendAsync(MessageType.NotFound, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false); return; }

        var m = _cache.TryLoadManifest(req.AssetId, req.Version);
        if (m is null || (uint)req.Index >= (uint)m.ChunkCount)
        { await s.SendAsync(MessageType.NotFound, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false); return; }

        var data = await _cache.ReadChunkAsync(m, req.Index, ct).ConfigureAwait(false);
        if (data is null) { await s.SendAsync(MessageType.NotFound, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false); return; }
        await _upload.AcquireAsync(data.Length, ct).ConfigureAwait(false);   // one shared upload budget for every peer
        await s.SendChunkAsync(req.Index, data, ct).ConfigureAwait(false);
    }

    private int _disposed;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return; // safe to call more than once
        _cts.Cancel();
        try { _listener.Stop(); } catch { }
        if (_acceptLoop is not null) { try { await _acceptLoop.ConfigureAwait(false); } catch { } }
        Task[] pending;
        lock (_tasksLock) pending = _tasks.ToArray();
        try { await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); } catch { }
        _cts.Dispose(); _cert.Dispose(); _slots.Dispose();
    }
}
