using System.Security.Cryptography;
using XMesh.Core;
using XMesh.Discovery;
using Xunit;

namespace XMesh.Tests;

public class DiscoveryTests
{
    [Fact]
    public void Beacon_roundtrips()
    {
        var id = new NodeId(RandomNumberGenerator.GetBytes(32));
        var b = LanDiscovery.EncodeBeacon(id, 5555);
        Assert.True(LanDiscovery.TryDecodeBeacon(b, out var id2, out var port));
        Assert.Equal(id, id2);
        Assert.Equal(5555, port);
    }

    [Fact]
    public void Malformed_beacons_are_ignored_not_thrown()
    {
        Assert.False(LanDiscovery.TryDecodeBeacon(new byte[10], out _, out _));
        Assert.False(LanDiscovery.TryDecodeBeacon(new byte[39], out _, out _));
        var id = new NodeId(RandomNumberGenerator.GetBytes(32));
        var b = LanDiscovery.EncodeBeacon(id, 5555);
        b[0] = (byte)'Z';
        Assert.False(LanDiscovery.TryDecodeBeacon(b, out _, out _));
        var b2 = LanDiscovery.EncodeBeacon(id, 5555); b2[4] = 99;
        Assert.False(LanDiscovery.TryDecodeBeacon(b2, out _, out _));
        var b3 = LanDiscovery.EncodeBeacon(id, 5555); b3[5] = 0; b3[6] = 0; // port 0
        Assert.False(LanDiscovery.TryDecodeBeacon(b3, out _, out _));
    }

    [Fact]
    public async Task Two_nodes_on_one_host_discover_each_other_over_loopback_broadcast()
    {
        var a = new NodeId(RandomNumberGenerator.GetBytes(32));
        var b = new NodeId(RandomNumberGenerator.GetBytes(32));
        int dport = 47700 + Random.Shared.Next(0, 200);
        await using var da = new LanDiscovery(a, 1111, dport, TimeSpan.FromMilliseconds(100));
        await using var db = new LanDiscovery(b, 2222, dport, TimeSpan.FromMilliseconds(100));
        da.Start(); db.Start();

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline && !(da.Peers.Any(p => p.Id.Equals(b)) && db.Peers.Any(p => p.Id.Equals(a))))
            await Task.Delay(50);

        Assert.Contains(da.Peers, p => p.Id.Equals(b) && p.Port == 2222);
        Assert.Contains(db.Peers, p => p.Id.Equals(a) && p.Port == 1111);
        Assert.DoesNotContain(da.Peers, p => p.Id.Equals(a)); // never lists itself
    }
}
