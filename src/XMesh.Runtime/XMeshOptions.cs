using XMesh.Core;
using XMesh.Security;

namespace XMesh.Runtime;

public sealed record XMeshOptions
{
    /// <summary>Directory holding identity.key, trust.json and the asset cache.</summary>
    public required string DataDir { get; init; }
    public XMeshPolicy Policy { get; init; } = new();
    /// <summary>TCP port to serve on; 0 picks a free port.</summary>
    public int ListenPort { get; init; } = 0;
    public bool EnableDiscovery { get; init; } = true;
    public int DiscoveryPort { get; init; } = XMesh.Discovery.LanDiscovery.DiscoveryPort;
    /// <summary>
    /// When the queue is empty but a chunk is stuck on a slow peer, let an idle peer fetch it too
    /// (first result wins; the loser is discarded). Costs at most one duplicate chunk per straggler.
    /// </summary>
    public bool HedgeSlowChunks { get; init; } = true;
    /// <summary>How long a chunk may be outstanding before an idle peer hedges it.</summary>
    public TimeSpan HedgeAfter { get; init; } = TimeSpan.FromMilliseconds(500);
    /// <summary>Disable to run as a pure client that never listens.</summary>
    public bool EnableServing { get; init; } = true;
    /// <summary>Provide a custom trust store (tests). Default is trust.json in DataDir.</summary>
    public ITrustStore? TrustStore { get; init; }
    /// <summary>Explicit static peers "host:port" tried in addition to LAN discovery.</summary>
    public IReadOnlyList<string> StaticPeers { get; init; } = Array.Empty<string>();
}
