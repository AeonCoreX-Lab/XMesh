using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using XMesh.Core;

namespace XMesh.Discovery;

public sealed record DiscoveredPeer(NodeId Id, IPAddress Address, int Port, DateTime LastSeenUtc);

/// <summary>
/// LAN peer discovery via UDP beacons (spec section 15). Beacon layout:
///   "XMAD" | version u8 | port u16 BE | nodeId(32)
/// Beacons are UNAUTHENTICATED hints. They only tell us where to try connecting; whether the peer
/// really owns that NodeId is proven by the XMA handshake, so a spoofed beacon can waste one
/// connection attempt but cannot impersonate a node or inject data.
/// </summary>
public sealed class LanDiscovery : IAsyncDisposable
{
    public const int DiscoveryPort = 47653;
    private const byte BeaconVersion = 1;
    private const int BeaconLength = 4 + 1 + 2 + NodeId.ByteLength;
    private static readonly byte[] Magic = "XMAD"u8.ToArray();

    private readonly NodeId _self;
    private readonly int _servicePort;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _ttl;
    private readonly int _discoveryPort;
    private readonly ConcurrentDictionary<string, DiscoveredPeer> _peers = new();
    private readonly CancellationTokenSource _cts = new();
    private UdpClient? _rx;
    private Task? _rxTask, _txTask;

    public LanDiscovery(NodeId self, int servicePort, int discoveryPort = DiscoveryPort,
        TimeSpan? interval = null, TimeSpan? ttl = null)
    {
        _self = self; _servicePort = servicePort; _discoveryPort = discoveryPort;
        _interval = interval ?? TimeSpan.FromSeconds(2);
        _ttl = ttl ?? TimeSpan.FromSeconds(10);
    }

    public IReadOnlyList<DiscoveredPeer> Peers
    {
        get
        {
            var cutoff = DateTime.UtcNow - _ttl;
            foreach (var kv in _peers) if (kv.Value.LastSeenUtc < cutoff) _peers.TryRemove(kv.Key, out _);
            return _peers.Values.ToList();
        }
    }

    public void Start()
    {
        _rx = new UdpClient(AddressFamily.InterNetwork);
        _rx.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _rx.Client.Bind(new IPEndPoint(IPAddress.Any, _discoveryPort));
        _rxTask = Task.Run(() => ReceiveLoopAsync(_cts.Token));
        _txTask = Task.Run(() => BroadcastLoopAsync(_cts.Token));
    }

    public static byte[] EncodeBeacon(NodeId id, int port)
    {
        var b = new byte[BeaconLength];
        Magic.CopyTo(b, 0);
        b[4] = BeaconVersion;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(5, 2), checked((ushort)port));
        id.Bytes.CopyTo(b.AsSpan(7));
        return b;
    }

    public static bool TryDecodeBeacon(ReadOnlySpan<byte> data, out NodeId id, out int port)
    {
        id = default; port = 0;
        if (data.Length != BeaconLength) return false;
        if (!data[..4].SequenceEqual(Magic) || data[4] != BeaconVersion) return false;
        port = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(5, 2));
        if (port == 0) return false;
        id = new NodeId(data.Slice(7, NodeId.ByteLength));
        return true;
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult r;
            try { r = await _rx!.ReceiveAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { continue; }

            if (!TryDecodeBeacon(r.Buffer, out var id, out var port)) continue;
            if (id.Equals(_self)) continue; // our own beacon
            _peers[id.ToHex()] = new DiscoveredPeer(id, r.RemoteEndPoint.Address, port, DateTime.UtcNow);
        }
    }

    private async Task BroadcastLoopAsync(CancellationToken ct)
    {
        var beacon = EncodeBeacon(_self, _servicePort);
        using var tx = new UdpClient(AddressFamily.InterNetwork) { EnableBroadcast = true };
        while (!ct.IsCancellationRequested)
        {
            foreach (var target in BroadcastTargets())
            {
                try { await tx.SendAsync(beacon, new IPEndPoint(target, _discoveryPort), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                catch (SocketException) { /* interface went away; try next round */ }
            }
            try { await Task.Delay(_interval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>Per-interface directed broadcast addresses, plus limited broadcast and loopback (same-host peers).</summary>
    internal static IEnumerable<IPAddress> BroadcastTargets()
    {
        var set = new HashSet<IPAddress> { IPAddress.Broadcast, IPAddress.Loopback };
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask is null) continue;
                    var ip = ua.Address.GetAddressBytes();
                    var mask = ua.IPv4Mask.GetAddressBytes();
                    var bc = new byte[4];
                    for (int i = 0; i < 4; i++) bc[i] = (byte)(ip[i] | ~mask[i]);
                    set.Add(new IPAddress(bc));
                }
            }
        }
        catch (NetworkInformationException) { }
        return set;
    }

    private int _disposed;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _cts.Cancel();
        _rx?.Dispose();
        if (_rxTask is not null) { try { await _rxTask.ConfigureAwait(false); } catch { } }
        if (_txTask is not null) { try { await _txTask.ConfigureAwait(false); } catch { } }
        _cts.Dispose();
    }
}
