using System.Collections.Concurrent;
using System.Text.Json;
using XMesh.Core;

namespace XMesh.Security;

/// <summary>Who this node trusts. Authentication != authorization (spec section 20).</summary>
public interface ITrustStore
{
    bool IsTrustedPublisher(string publisherKeyHex);
    bool IsAllowedPeer(NodeId peer);
}

/// <summary>JSON-file-backed allowlist. Default policy is restrictive (spec section 45).</summary>
public sealed class FileTrustStore : ITrustStore
{
    private readonly string _path;
    private readonly ConcurrentDictionary<string, byte> _publishers = new();
    private readonly ConcurrentDictionary<string, byte> _peers = new();

    private sealed class Model
    {
        public List<string> Publishers { get; set; } = new();
        public List<string> Peers { get; set; } = new();
    }

    public FileTrustStore(string path)
    {
        _path = path;
        if (!File.Exists(path)) return;
        Model? m;
        try { m = JsonSerializer.Deserialize<Model>(File.ReadAllText(path)); }
        catch (JsonException ex) { throw new XMeshException(XMeshErrorCode.PolicyDenied, $"Trust file '{path}' is corrupt.", ex); }
        if (m is null) return;
        foreach (var p in m.Publishers) _publishers[p.ToLowerInvariant()] = 0;
        foreach (var p in m.Peers) _peers[p.ToLowerInvariant()] = 0;
    }

    public bool IsTrustedPublisher(string publisherKeyHex) => _publishers.ContainsKey(publisherKeyHex.ToLowerInvariant());
    public bool IsAllowedPeer(NodeId peer) => _peers.ContainsKey(peer.ToHex());

    public void TrustPublisher(string publisherKeyHex) { _publishers[publisherKeyHex.ToLowerInvariant()] = 0; Save(); }
    public void AllowPeer(NodeId peer) { _peers[peer.ToHex()] = 0; Save(); }
    public void RevokePeer(NodeId peer) { _peers.TryRemove(peer.ToHex(), out _); Save(); }

    private readonly object _saveLock = new();
    private void Save()
    {
        lock (_saveLock)
        {
            var m = new Model { Publishers = _publishers.Keys.Order().ToList(), Peers = _peers.Keys.Order().ToList() };
            var dir = Path.GetDirectoryName(Path.GetFullPath(_path));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(m, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, _path, overwrite: true);
        }
    }
}

/// <summary>In-memory store for tests and embedded use.</summary>
public sealed class MemoryTrustStore : ITrustStore
{
    private readonly HashSet<string> _publishers = new();
    private readonly HashSet<string> _peers = new();
    private readonly object _l = new();
    public bool AllowAllPeers { get; init; }

    public bool IsTrustedPublisher(string k) { lock (_l) return _publishers.Contains(k.ToLowerInvariant()); }
    public bool IsAllowedPeer(NodeId p) { lock (_l) return AllowAllPeers || _peers.Contains(p.ToHex()); }
    public void TrustPublisher(string k) { lock (_l) _publishers.Add(k.ToLowerInvariant()); }
    public void AllowPeer(NodeId p) { lock (_l) _peers.Add(p.ToHex()); }
}
