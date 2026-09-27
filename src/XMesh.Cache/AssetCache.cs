using System.Buffers;
using Microsoft.Win32.SafeHandles;
using System.Text.Json;
using XMesh.Assets;
using XMesh.Core;

namespace XMesh.Cache;

/// <summary>
/// Manifest-aware, resumable, verified local cache (spec sections 21, 22).
///
/// Layout:  {root}/{assetId}/{version}/manifest.json
///                                   /data.part      (sparse, written by chunk offset)
///                                   /state.json     (which chunks are verified)
///                                   /data.bin       (final, after all chunks verified)
///
/// Only chunks that passed SHA-256 verification are ever marked complete, so a crash
/// mid-transfer can never produce a "complete" asset containing unverified bytes.
/// </summary>
public sealed class AssetCache
{
    private readonly string _root;
    private readonly long _maxBytes;
    private readonly object _gate = new();

    /// <summary>How many verified chunks between resume-state saves. Lower = safer resume, more I/O.</summary>
    public int StateSaveInterval { get; }

    public AssetCache(string root, long maxBytes, int stateSaveInterval = 8)
    {
        if (stateSaveInterval < 1) throw new ArgumentOutOfRangeException(nameof(stateSaveInterval));
        StateSaveInterval = stateSaveInterval;
        _root = Path.GetFullPath(root);
        _maxBytes = maxBytes;
        Directory.CreateDirectory(_root);
    }

    public string Root => _root;

    private string Dir(string assetId, string version)
    {
        // Tokens are validated in the manifest; re-check here as defence in depth (path traversal).
        if (!AssetManifest.IsSafeToken(assetId) || !AssetManifest.IsSafeToken(version))
            throw new XMeshException(XMeshErrorCode.ManifestInvalid, "Unsafe asset path component.");
        var full = Path.GetFullPath(Path.Combine(_root, assetId, version));
        if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new XMeshException(XMeshErrorCode.ManifestInvalid, "Asset path escapes cache root.");
        return full;
    }

    public string FinalPath(string assetId, string version) => Path.Combine(Dir(assetId, version), "data.bin");

    /// <summary>True only if the fully verified asset is present.</summary>
    public bool IsComplete(AssetManifest m)
    {
        var f = FinalPath(m.AssetId, m.Version);
        return File.Exists(f) && new FileInfo(f).Length == m.Size && File.Exists(Path.Combine(Dir(m.AssetId, m.Version), "complete"));
    }

    public AssetManifest? TryLoadManifest(string assetId, string version)
    {
        var p = Path.Combine(Dir(assetId, version), "manifest.json");
        if (!File.Exists(p)) return null;
        try { return AssetManifest.FromJson(File.ReadAllText(p)); }
        catch (XMeshException) { return null; }
    }

    /// <summary>Open a resumable download session for this manifest.</summary>
    public CacheSession OpenSession(AssetManifest m)
    {
        m.Validate();
        var dir = Dir(m.AssetId, m.Version);
        Directory.CreateDirectory(dir);
        var manifestPath = Path.Combine(dir, "manifest.json");

        // If a different manifest (different content) is already cached for this id@version, discard stale state.
        var existing = TryLoadManifest(m.AssetId, m.Version);
        if (existing is not null && existing.ComputeRoot() != m.ComputeRoot())
        {
            foreach (var f in Directory.GetFiles(dir)) File.Delete(f);
        }
        var json = m.ToJson();
        if (!File.Exists(manifestPath) || File.ReadAllText(manifestPath) != json) WriteAtomic(manifestPath, json);
        return new CacheSession(this, m, dir);
    }

    public bool Delete(string assetId, string version)
    {
        var d = Dir(assetId, version);
        if (!Directory.Exists(d)) return false;
        Directory.Delete(d, recursive: true);
        return true;
    }

    public IReadOnlyList<CachedAsset> List()
    {
        var res = new List<CachedAsset>();
        foreach (var aDir in Directory.EnumerateDirectories(_root))
        foreach (var vDir in Directory.EnumerateDirectories(aDir))
        {
            var id = Path.GetFileName(aDir);
            var ver = Path.GetFileName(vDir);
            var man = TryLoadManifest(id, ver);
            if (man is null) continue;
            long size = Directory.EnumerateFiles(vDir).Sum(f => new FileInfo(f).Length);
            bool complete = File.Exists(Path.Combine(vDir, "complete"));
            res.Add(new CachedAsset(id, ver, man.Size, size, complete, LastUsedUtc(vDir)));
        }
        return res;
    }

    /// <summary>LRU eviction of complete assets until total usage fits the budget. Returns bytes freed.</summary>
    public long Evict(IReadOnlySet<string>? pinned = null)
    {
        lock (_gate)
        {
            var all = List();
            long used = all.Sum(a => a.OnDiskBytes);
            if (_maxBytes <= 0 || used <= _maxBytes) return 0;
            long freed = 0;
            foreach (var a in all.Where(a => a.Complete && pinned?.Contains($"{a.AssetId}@{a.Version}") != true)
                                 .OrderBy(a => a.LastAccessUtc))
            {
                if (used - freed <= _maxBytes) break;
                if (Delete(a.AssetId, a.Version)) freed += a.OnDiskBytes;
            }
            return freed;
        }
    }

    /// <summary>
    /// Read-only chunk read for serving peers. Does NOT open a download session, does not rewrite
    /// the manifest, and never mutates cache state. Serves from the final file when complete,
    /// otherwise from the .part file only for chunks recorded as verified in state.json.
    /// The bytes are re-verified against the manifest before being returned.
    /// </summary>
    public async Task<byte[]?> ReadChunkAsync(AssetManifest m, int index, CancellationToken ct = default)
    {
        if ((uint)index >= (uint)m.ChunkCount) return null;
        var dir = Dir(m.AssetId, m.Version);
        int len = m.ChunkLength(index);
        long offset = (long)index * m.ChunkSize;
        var buf = new byte[len];

        string? path = null;
        if (File.Exists(Path.Combine(dir, "complete")) && File.Exists(Path.Combine(dir, "data.bin")))
            path = Path.Combine(dir, "data.bin");
        else if (File.Exists(Path.Combine(dir, "data.part")) && IsChunkRecorded(dir, m, index))
            path = Path.Combine(dir, "data.part");
        if (path is null) return null;

        try
        {
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.Asynchronous);
            if (fs.Length < offset + len) return null;
            fs.Position = offset;
            await fs.ReadExactlyAsync(buf, ct).ConfigureAwait(false);
        }
        catch (IOException) { return null; }

        return ChunkVerifier.Verify(m, index, buf) ? buf : null;
    }

    private static bool IsChunkRecorded(string dir, AssetManifest m, int index)
    {
        var p = Path.Combine(dir, "state.json");
        if (!File.Exists(p)) return false;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(p));
            var root = doc.RootElement;
            if (root.GetProperty("Root").GetString() != m.ComputeRoot()) return false;
            var bits = root.GetProperty("Bits").GetString();
            return bits is not null && index < bits.Length && bits[index] == '1';
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or IOException) { return false; }
    }

    /// <summary>
    /// Mark an asset as recently used (drives LRU eviction).
    /// Recency is stored as the LAST-WRITE time of a dedicated "used" marker file rather than the directory's
    /// access time: filesystem atime is unreliable (noatime/relatime mounts, network filesystems), so it
    /// cannot be trusted for eviction order.
    /// </summary>
    public void Touch(string assetId, string version) => TouchAt(assetId, version, DateTime.UtcNow);

    /// <summary>Test/maintenance hook: set an explicit last-used time.</summary>
    public void TouchAt(string assetId, string version, DateTime utc)
    {
        try
        {
            var marker = Path.Combine(Dir(assetId, version), "used");
            if (!File.Exists(marker)) File.WriteAllBytes(marker, Array.Empty<byte>());
            File.SetLastWriteTimeUtc(marker, utc);
        }
        catch (IOException) { /* recency is best-effort bookkeeping; never fail a transfer over it */ }
        catch (UnauthorizedAccessException) { }
    }

    private DateTime LastUsedUtc(string dir)
    {
        var marker = Path.Combine(dir, "used");
        if (File.Exists(marker)) return File.GetLastWriteTimeUtc(marker);
        var manifest = Path.Combine(dir, "manifest.json");   // never touched: fall back to creation time
        return File.Exists(manifest) ? File.GetLastWriteTimeUtc(manifest) : DateTime.MinValue;
    }

    internal static void WriteAtomic(string path, string content)
    {
        // Unique temp name per call: two concurrent writers must never share a temp file.
        var tmp = $"{path}.{Environment.CurrentManagedThreadId}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(tmp, content);
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch (IOException) { }
            throw;
        }
    }
}

public sealed record CachedAsset(string AssetId, string Version, long Size, long OnDiskBytes, bool Complete, DateTime LastAccessUtc);

/// <summary>One resumable download of a single asset.</summary>
public sealed class CacheSession : IDisposable
{

    private readonly AssetCache _cache;
    private readonly string _dir;
    private readonly bool[] _have;
    private readonly SafeFileHandle? _handle;
    private readonly object _lock = new();
    private int _unsaved;
    private bool _finalized;
    private bool _disposed;

    public AssetManifest Manifest { get; }

    internal CacheSession(AssetCache cache, AssetManifest m, string dir)
    {
        _cache = cache; Manifest = m; _dir = dir;
        _have = new bool[m.ChunkCount];

        if (File.Exists(Path.Combine(dir, "complete")))
        {
            Array.Fill(_have, true);
            _finalized = true;
            return;
        }

        var partPath = Path.Combine(dir, "data.part");
        _handle = File.OpenHandle(partPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, FileOptions.Asynchronous);
        LoadState(m);
        if (RandomAccess.GetLength(_handle) != m.Size) RandomAccess.SetLength(_handle, m.Size);
    }

    public int ChunkCount => Manifest.ChunkCount;
    public bool IsFinalized => _finalized;
    public int CompletedCount { get { lock (_lock) return _have.Count(x => x); } }
    public bool Has(int index) { lock (_lock) return (uint)index < (uint)_have.Length && _have[index]; }

    public IReadOnlyList<int> Missing()
    {
        lock (_lock)
        {
            var r = new List<int>();
            for (int i = 0; i < _have.Length; i++) if (!_have[i]) r.Add(i);
            return r;
        }
    }

    /// <summary>
    /// Verify, then persist at the exact chunk offset. Bytes that fail SHA-256 verification are
    /// NEVER written. Uses RandomAccess so concurrent chunk writes cannot race on a shared position.
    /// </summary>
    public async Task WriteChunkAsync(int index, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_finalized) return;
        ChunkVerifier.VerifyOrThrow(Manifest, index, data.Span);

        lock (_lock) { if (_have[index]) return; }

        long offset = (long)index * Manifest.ChunkSize;
        await RandomAccess.WriteAsync(_handle!, data, offset, ct).ConfigureAwait(false);

        bool flush;
        lock (_lock)
        {
            _have[index] = true;
            flush = ++_unsaved >= _cache.StateSaveInterval;
            if (flush) _unsaved = 0;
        }
        if (flush) SaveState();
    }

    /// <summary>Read a chunk from a partially or fully downloaded asset (used to serve peers).</summary>
    public async Task<byte[]?> ReadChunkAsync(int index, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!Has(index)) return null;
        int len = Manifest.ChunkLength(index);
        var buf = new byte[len];
        long offset = (long)index * Manifest.ChunkSize;

        if (_finalized)
        {
            await using var fs = new FileStream(_cache.FinalPath(Manifest.AssetId, Manifest.Version),
                FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.Asynchronous);
            fs.Position = offset;
            await fs.ReadExactlyAsync(buf, ct).ConfigureAwait(false);
        }
        else
        {
            int read = 0;
            while (read < len)
            {
                int n = await RandomAccess.ReadAsync(_handle!, buf.AsMemory(read), offset + read, ct).ConfigureAwait(false);
                if (n == 0) return null;
                read += n;
            }
        }
        // Re-verify on read: protects against on-disk corruption being served to peers.
        return ChunkVerifier.Verify(Manifest, index, buf) ? buf : null;
    }

    /// <summary>
    /// Finish the asset: requires every chunk complete, re-verifies the whole file, then atomically
    /// renames data.part to data.bin and drops a "complete" marker.
    /// </summary>
    public async Task FinalizeAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_finalized) return;
        if (Missing().Count != 0)
            throw new XMeshException(XMeshErrorCode.ChunkHashMismatch, "Cannot finalize: chunks missing.");

        // Full re-verification pass over the on-disk bytes.
        var buf = ArrayPool<byte>.Shared.Rent(Manifest.ChunkSize);
        try
        {
            for (int i = 0; i < Manifest.ChunkCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                int len = Manifest.ChunkLength(i);
                long off = (long)i * Manifest.ChunkSize;
                int read = 0;
                while (read < len)
                {
                    int n = await RandomAccess.ReadAsync(_handle!, buf.AsMemory(read, len - read), off + read, ct).ConfigureAwait(false);
                    if (n == 0) throw new XMeshException(XMeshErrorCode.ChunkHashMismatch, "Short read during finalize.");
                    read += n;
                }
                ChunkVerifier.VerifyOrThrow(Manifest, i, buf.AsSpan(0, len));
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }

        RandomAccess.FlushToDisk(_handle!);
        _handle!.Dispose();

        var part = Path.Combine(_dir, "data.part");
        var final = Path.Combine(_dir, "data.bin");
        File.Move(part, final, overwrite: true);
        File.WriteAllText(Path.Combine(_dir, "complete"), Manifest.ComputeRoot());
        lock (_saveLock)
        {
            _finalized = true;
            var state = Path.Combine(_dir, "state.json");
            if (File.Exists(state)) File.Delete(state);
        }
        _cache.Touch(Manifest.AssetId, Manifest.Version);
    }

    private sealed class StateModel
    {
        public string Root { get; set; } = "";
        public string Bits { get; set; } = "";
    }

    private void LoadState(AssetManifest m)
    {
        var p = Path.Combine(_dir, "state.json");
        if (!File.Exists(p)) return;
        try
        {
            var s = JsonSerializer.Deserialize<StateModel>(File.ReadAllText(p));
            if (s is null || s.Root != m.ComputeRoot() || s.Bits.Length != _have.Length) return;
            for (int i = 0; i < _have.Length; i++) _have[i] = s.Bits[i] == '1';
        }
        catch (JsonException) { /* corrupt state => start over; verification protects correctness */ }
    }

    private readonly object _saveLock = new();

    private void SaveState()
    {
        // Serialized, and the snapshot is taken INSIDE the save lock: whichever save runs last always
        // captures the newest bitmap, so an older snapshot can never overwrite a newer one.
        lock (_saveLock)
        {
            if (_finalized) return;
            string bits;
            lock (_lock) bits = string.Create(_have.Length, _have, static (span, h) => { for (int i = 0; i < h.Length; i++) span[i] = h[i] ? '1' : '0'; });
            var model = new StateModel { Root = Manifest.ComputeRoot(), Bits = bits };
            AssetCache.WriteAtomic(Path.Combine(_dir, "state.json"), JsonSerializer.Serialize(model));
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (!_finalized) { try { SaveState(); } catch (IOException) { } }
        _handle?.Dispose();
    }
}
