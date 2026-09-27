using System.Diagnostics;
using System.Net;
using XMesh.Assets;
using XMesh.Cache;
using XMesh.Core;
using XMesh.Discovery;
using XMesh.Protocol;
using XMesh.Security;
using XMesh.Transport;

namespace XMesh.Runtime;

/// <summary>
/// The XMA runtime: the single object an application talks to (spec section 27).
/// Delivery order (policy-driven, spec sections 13 and 40):  local cache -> LAN/static peers -> origin.
/// Every chunk, from every source, is SHA-256 verified against the signed manifest before it is cached.
/// </summary>
public sealed class XMeshRuntime : IAsyncDisposable
{
    private readonly XMeshOptions _opt;
    private readonly SemaphoreSlim _transferSlots;
    private readonly RateLimiter _download;
    private readonly Dictionary<string, Task<AssetResult>> _inflight = new();
    private readonly object _inflightLock = new();
    private LanDiscovery? _discovery;
    private PeerServer? _server;
    private OriginClient? _origin;

    public NodeIdentity Identity { get; }
    public ITrustStore Trust { get; }
    public AssetCache Cache { get; }
    public int ListenPort => _server?.Port ?? 0;

    /// <summary>Raised on every state transition of every transfer.</summary>
    public event Action<TransferProgress>? Progress;
    public event Action<string>? Log;

    public XMeshRuntime(XMeshOptions options)
    {
        options.Policy.Validate();
        _opt = options;
        Directory.CreateDirectory(options.DataDir);
        Identity = NodeIdentity.LoadOrCreate(Path.Combine(options.DataDir, "identity.key"));
        Trust = options.TrustStore ?? new FileTrustStore(Path.Combine(options.DataDir, "trust.json"));
        Cache = new AssetCache(Path.Combine(options.DataDir, "cache"), options.Policy.MaxCacheSizeBytes);
        _transferSlots = new SemaphoreSlim(options.Policy.MaxConcurrentTransfers, options.Policy.MaxConcurrentTransfers);
        _download = new RateLimiter(options.Policy.EffectiveDownloadLimit);
    }

    public Task StartAsync()
    {
        _origin = new OriginClient();
        if (_opt.EnableServing && _opt.Policy.AllowServing)
        {
            _server = new PeerServer(Cache, Identity, Trust, _opt.Policy, port: _opt.ListenPort);
            _server.Log += m => Log?.Invoke(m);
            _server.Start();
            if (_opt.EnableDiscovery)
            {
                _discovery = new LanDiscovery(Identity.Id, _server.Port, _opt.DiscoveryPort);
                _discovery.Start();
            }
        }
        else if (_opt.EnableDiscovery)
        {
            // Client-only nodes still LISTEN for beacons to find servers (they just don't announce a port).
            // We reuse LanDiscovery with port 1 only for its receive side; nothing connects to a client-only node.
            _discovery = new LanDiscovery(Identity.Id, servicePort: 1, _opt.DiscoveryPort);
            _discovery.Start();
        }
        Log?.Invoke($"node {Identity.Id.Short} started, port {ListenPort}");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Get an asset. Concurrent requests for the same asset@version share one transfer.
    /// The manifest MUST be signed by a trusted publisher; otherwise the request fails.
    /// </summary>
    public Task<AssetResult> GetAssetAsync(AssetRequest request, AssetManifest manifest, CancellationToken ct = default)
    {
        var key = $"{request.AssetId}@{request.Version}";
        lock (_inflightLock)
        {
            if (_inflight.TryGetValue(key, out var existing)) return existing;
            var task = TrackAsync(key, request, manifest, ct);
            _inflight[key] = task;
            return task;
        }
    }

    /// <summary>
    /// Runs the transfer and removes its own in-flight entry BEFORE the returned task completes.
    /// (Removing it from a ContinueWith continuation races with the caller: the caller can observe the
    /// failed task, retry immediately, and still find the stale failed task registered.)
    /// </summary>
    private async Task<AssetResult> TrackAsync(string key, AssetRequest request, AssetManifest manifest, CancellationToken ct)
    {
        // Yield so the registration in GetAssetAsync (done under the lock) always happens-before
        // this method's finally block, even if RunTransferAsync completes synchronously.
        await Task.Yield();
        try { return await RunTransferAsync(request, manifest, ct).ConfigureAwait(false); }
        finally { lock (_inflightLock) _inflight.Remove(key); }
    }

    private async Task<AssetResult> RunTransferAsync(AssetRequest req, AssetManifest manifest, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        long fromCache = 0, fromPeers = 0, fromOrigin = 0;
        int chunksTotal = manifest.ChunkCount;

        void Report(TransferState st, AssetSource? src, long done, int chunks) =>
            Progress?.Invoke(new TransferProgress(req.AssetId, st, done, manifest.Size, chunks, chunksTotal, src));

        try
        {
            Report(TransferState.Resolving, null, 0, 0);
            if (manifest.AssetId != req.AssetId || manifest.Version != req.Version)
                throw new XMeshException(XMeshErrorCode.ManifestInvalid, "Manifest does not match the requested asset/version.");
            // Publisher authenticity + structure. A hash alone proves nothing about who published it.
            ManifestSigner.VerifyOrThrow(manifest, Trust);

            await _transferSlots.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                Report(TransferState.CheckingCache, null, 0, 0);

                if (Cache.IsComplete(manifest))
                {
                    Cache.Touch(req.AssetId, req.Version); // LRU bookkeeping only; no writes
                    Report(TransferState.Completed, AssetSource.Cache, manifest.Size, chunksTotal);
                    return new AssetResult(req.AssetId, req.Version, manifest.Size,
                        Cache.FinalPath(req.AssetId, req.Version), true, manifest.Size, 0, 0, sw.Elapsed);
                }

                using var session = Cache.OpenSession(manifest);
                // Bytes already verified on disk from a previous attempt count as cache hits (resume).
                for (int i = 0; i < chunksTotal; i++) if (session.Has(i)) fromCache += manifest.ChunkLength(i);
                int done = session.CompletedCount;
                Report(TransferState.Transferring, AssetSource.Cache, fromCache, done);

                var missing = session.Missing().ToList();
                if (missing.Count > 0)
                {
                    // ---- peers ---------------------------------------------------------
                    if (req.AllowPeers)
                    {
                        Report(TransferState.DiscoveringPeers, null, fromCache, done);
                        var got = await FetchFromPeersAsync(manifest, session, missing, (bytes, chunks) =>
                        {
                            Report(TransferState.Transferring, AssetSource.Peer, fromCache + bytes, done + chunks);
                        }, ct).ConfigureAwait(false);
                        fromPeers = got;
                        missing = session.Missing().ToList();
                        done = session.CompletedCount;
                    }

                    // ---- origin fallback ----------------------------------------------
                    if (missing.Count > 0)
                    {
                        if (!req.AllowOrigin || manifest.Origin is null)
                            throw new XMeshException(XMeshErrorCode.OriginUnavailable,
                                $"{missing.Count} chunk(s) unavailable from peers and origin fallback is not available.");

                        long baseBytes = fromCache + fromPeers;
                        fromOrigin = await FetchFromOriginAsync(manifest, session, missing, bytes =>
                        {
                            Report(TransferState.Transferring, AssetSource.Origin, baseBytes + bytes, session.CompletedCount);
                        }, ct).ConfigureAwait(false);
                    }
                }

Report(TransferState.Verifying, null, manifest.Size, chunksTotal);
                Report(TransferState.Caching, null, manifest.Size, chunksTotal);
await session.FinalizeAsync(ct).ConfigureAwait(false);
                Cache.Evict(new HashSet<string> { $"{req.AssetId}@{req.Version}" });

                Report(TransferState.Completed, null, manifest.Size, chunksTotal);
                return new AssetResult(req.AssetId, req.Version, manifest.Size,
                    Cache.FinalPath(req.AssetId, req.Version), true, fromCache, fromPeers, fromOrigin, sw.Elapsed);
            }
            finally { _transferSlots.Release(); }
        }
        catch (OperationCanceledException)
        {
            Report(TransferState.Cancelled, null, 0, 0);
            throw;
        }
        catch
        {
            Report(TransferState.Failed, null, 0, 0);
            throw;
        }
    }

    // ------------------------------------------------------------------------- peers

    private IEnumerable<(string Host, int Port)> CandidatePeers()
    {
        var seen = new HashSet<string>();
        foreach (var sp in _opt.StaticPeers)
        {
            var i = sp.LastIndexOf(':');
            if (i > 0 && int.TryParse(sp[(i + 1)..], out var p) && seen.Add(sp)) yield return (sp[..i], p);
        }
        if (_discovery is not null)
            foreach (var d in _discovery.Peers)
                if (seen.Add($"{d.Address}:{d.Port}") && d.Port != 1) yield return (d.Address.ToString(), d.Port);
    }

    /// <summary>
    /// Pull missing chunks from every reachable, authorized peer using a shared <see cref="ChunkWorkQueue"/>.
    ///  * A chunk a peer lacks is handed to other peers.
    ///  * A failed/slow peer's chunk is handed to other peers.
    ///  * A peer that sends bytes failing verification is dropped for the rest of the transfer.
    ///  * When the queue runs dry but a chunk is still stuck on a slow peer, an idle peer hedges it
    ///    (spec section 41), so one straggler cannot hold up the whole asset.
    /// Whatever no peer could supply is left missing and falls through to the origin.
    /// </summary>
    private async Task<long> FetchFromPeersAsync(AssetManifest m, CacheSession session, List<int> missing,
        Action<long, int> onProgress, CancellationToken ct)
    {
        long total = 0;
        int chunkCount = 0;

        var peers = CandidatePeers().ToList();
        if (peers.Count == 0) return 0;

        var work = new ChunkWorkQueue(missing, _opt.HedgeSlowChunks, _opt.HedgeAfter);

        // Workers stop when every chunk is done, OR when no live worker remains that could still make progress
        // (otherwise a chunk nobody has would leave the survivors waiting forever).
        var liveWorkers = new HashSet<int>(Enumerable.Range(0, peers.Count));
        var liveLock = new object();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);

        void WorkerExited(int workerId)
        {
            bool stuck;
            lock (liveLock)
            {
                liveWorkers.Remove(workerId);
                stuck = liveWorkers.Count == 0 || work.IsStuck(liveWorkers);
            }
            if (stuck) stop.Cancel();
        }

        bool CheckStuckAfterDecline()
        {
            lock (liveLock) return work.IsStuck(liveWorkers);
        }

        async Task WorkerAsync((string Host, int Port) peer, int workerId)
        {
            PeerSession? ps = null;
            try
            {
                ps = await PeerSession.ConnectAsync(peer.Host, peer.Port, Identity, Trust, _opt.Policy, stop.Token).ConfigureAwait(false);
                if (!ps.RemoteCanServe) return;
                var client = new PeerClient(ps);

                // Confirm the peer has THIS exact content (same signed manifest root) before asking for chunks.
                var theirs = await client.GetManifestAsync(m.AssetId, m.Version, stop.Token).ConfigureAwait(false);
                if (theirs is null || theirs.ComputeRoot() != m.ComputeRoot()) return;

                while (true)
                {
                    (bool Ok, ChunkWorkQueue.Lease Lease) next;
                    try { next = await work.NextAsync(workerId, stop.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { return; }      // finished, or every other worker is gone
                    if (!next.Ok) return;
                    var lease = next.Lease;
                    int idx = lease.Index;

                    if (session.Has(idx)) { work.Complete(idx); continue; }

                    // 'data' is a LEASE from the buffer pool, released in the finally on EVERY exit path.
                    PooledBuffer? data = null;
                    bool handled = false;
                    try
                    {
                        // The chunk was already completed by a DIFFERENT fetcher (a hedge won, or this lease
                        // WAS the hedge and the original beat it) while this lease sat unclaimed. Nothing to do.
                        if (lease.RaceCancellation.IsCancellationRequested) { handled = true; continue; }

                        bool transportFailed = false;
                        for (int attempt = 0; attempt <= _opt.Policy.MaxChunkRetries && data is null; attempt++)
                        {
                            // Link in the lease's race-cancellation token: the instant ANY fetcher
                            // (this one, a hedge, or the original) completes this chunk, every other
                            // in-flight fetch for it must stop immediately rather than run to completion.
                            using var to = CancellationTokenSource.CreateLinkedTokenSource(stop.Token, lease.RaceCancellation);
                            to.CancelAfter(_opt.Policy.ChunkTimeout);
                            try
                            {
                                data = await client.GetChunkPooledAsync(m.AssetId, m.Version, idx, to.Token).ConfigureAwait(false);
                                if (data is not null) await _download.AcquireAsync(data.Length, stop.Token).ConfigureAwait(false);
                            }
                            catch (OperationCanceledException) when (lease.RaceCancellation.IsCancellationRequested)
                            {
                                // Cancelled because another fetcher already finished this chunk - not a real
                                // failure. Do NOT requeue/decline/fail it: it is already done.
                                handled = true; data?.Dispose(); data = null; goto raceLost;
                            }
                            catch (OperationCanceledException) when (!stop.IsCancellationRequested) { transportFailed = true; break; }
                            catch (Exception ex) when (ex is XMeshException or IOException or System.Net.Sockets.SocketException)
                            {
                                work.Failed(idx, lease.IsHedge);   // hand the chunk to a healthy peer
                                handled = true;
                                throw;                             // and abandon this (broken) connection
                            }
                            if (data is null) break;               // NotFound: this peer does not hold this chunk
                        }
                        raceLost:

                        if (lease.RaceCancellation.IsCancellationRequested) continue;   // handled above; move on

                        if (data is null)
                        {
                            handled = true;
                            if (transportFailed) { work.Failed(idx, lease.IsHedge); return; }   // hung peer: give the chunk back, stop
                            work.Decline(idx, workerId, lease.IsHedge);   // other peers may have it; this one is never re-offered it
                            if (CheckStuckAfterDecline()) stop.Cancel();      // nobody LIVE can help: fall back
                            continue;
                        }

                        try { await session.WriteChunkAsync(idx, data.Memory, stop.Token).ConfigureAwait(false); }
                        catch (XMeshException ex) when (ex.Code == XMeshErrorCode.ChunkHashMismatch)
                        {
                            Log?.Invoke($"peer {ps.RemoteId.Short} sent a bad chunk {idx}; dropping peer");
                            work.Failed(idx, lease.IsHedge);
                            handled = true;
                            return;
                        }

                        // Count bytes only for the FIRST completion: a hedge that loses the race is not double-counted.
                        if (work.Complete(idx))
                        {
                            var b = Interlocked.Add(ref total, data.Length);
                            var c = Interlocked.Increment(ref chunkCount);
                            onProgress(b, c);
                        }
                        handled = true;
                    }
                    catch (OperationCanceledException) when (stop.IsCancellationRequested)
                    {
                        if (!handled) work.Failed(idx, lease.IsHedge);
                        return;
                    }
                    finally
                    {
                        data?.Dispose();
                        if (!handled) work.Failed(idx, lease.IsHedge);   // last-resort safety net: never strand a chunk
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; // the caller cancelled: honour it
            }
            catch (Exception ex)
            {
                // Peers are untrusted and unreliable BY DESIGN. Whatever goes wrong with one of them costs us
                // only that peer; the missing chunks fall through to other peers and finally to the origin.
                Log?.Invoke($"peer {peer.Host}:{peer.Port} skipped: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                if (ps is not null) await ps.DisposeAsync().ConfigureAwait(false);
                WorkerExited(workerId);
            }
        }

        await Task.WhenAll(peers.Select((p, i) => WorkerAsync(p, i))).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return Interlocked.Read(ref total);
    }

    // ------------------------------------------------------------------------- origin

    private async Task<long> FetchFromOriginAsync(AssetManifest m, CacheSession session, List<int> missing,
        Action<long> onProgress, CancellationToken ct)
    {
        long total = 0;
        var queue = new System.Collections.Concurrent.ConcurrentQueue<int>(missing);
        int workers = Math.Min(_opt.Policy.MaxConnections, Math.Max(1, missing.Count));

        async Task WorkerAsync()
        {
            while (queue.TryDequeue(out var idx))
            {
                if (session.Has(idx)) continue;
                Exception? last = null;
                bool ok = false;
                for (int attempt = 0; attempt <= _opt.Policy.MaxChunkRetries && !ok; attempt++)
                {
                    ct.ThrowIfCancellationRequested();
                    using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    to.CancelAfter(_opt.Policy.ChunkTimeout);
                    try
                    {
                        using var data = await _origin!.GetChunkPooledAsync(m, idx, to.Token).ConfigureAwait(false);
                        await _download.AcquireAsync(data.Length, ct).ConfigureAwait(false);
                        await session.WriteChunkAsync(idx, data.Memory, ct).ConfigureAwait(false);   // verifies before persisting
                        onProgress(Interlocked.Add(ref total, data.Length));
                        ok = true;
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { last = new TimeoutException("chunk timeout"); }
                    catch (XMeshException ex) when (ex.Code is XMeshErrorCode.OriginUnavailable or XMeshErrorCode.ChunkHashMismatch) { last = ex; }
                    catch (EndOfStreamException ex) { last = ex; }
                    if (!ok) await Task.Delay(TimeSpan.FromMilliseconds(200 * (attempt + 1)), ct).ConfigureAwait(false);
                }
                if (!ok)
                    throw new XMeshException(XMeshErrorCode.OriginUnavailable,
                        $"Chunk {idx} could not be fetched from origin after {_opt.Policy.MaxChunkRetries + 1} attempts: {last?.Message}", last);
            }
        }

        await Task.WhenAll(Enumerable.Range(0, workers).Select(_ => WorkerAsync())).ConfigureAwait(false);
        return Interlocked.Read(ref total);
    }

    // ------------------------------------------------------------------------- misc

    /// <summary>Open a read stream over a completed, verified asset.</summary>
    public async Task<Stream> OpenStreamAsync(AssetRequest request, AssetManifest manifest, CancellationToken ct = default)
    {
        var r = await GetAssetAsync(request, manifest, ct).ConfigureAwait(false);
        return new FileStream(r.LocalPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
    }

    public Task PrefetchAsync(AssetRequest request, AssetManifest manifest, CancellationToken ct = default) =>
        GetAssetAsync(request, manifest, ct);

    public IReadOnlyList<DiscoveredPeer> DiscoveredPeers => _discovery?.Peers ?? Array.Empty<DiscoveredPeer>();

    private int _disposed;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return; // safe to call more than once
        if (_discovery is not null) await _discovery.DisposeAsync().ConfigureAwait(false);
        if (_server is not null) await _server.DisposeAsync().ConfigureAwait(false);
        _origin?.Dispose();
        Identity.Dispose();
        _transferSlots.Dispose();
    }
}
