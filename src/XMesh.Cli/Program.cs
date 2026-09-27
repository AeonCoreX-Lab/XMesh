using XMesh.Assets;
using XMesh.Core;
using XMesh.Runtime;
using XMesh.Security;

namespace XMesh.Cli;

internal static class Program
{
    private static readonly OptionSpec DataDir =
        new("data-dir", 'd', true, "XMA data directory (identity, trust, cache). Default: ~/.xma");

    private const string Help = """
        X-Mesh Agent Engine (XMA) - distributed asset delivery runtime

        usage: xma [--data-dir <dir>] <command> [options]

        commands:
          init                          create this node's identity, print NodeId + public key
          publish <file> --id --version chunk, hash and sign a file; import it into the local cache
          verify <manifest>             check a manifest's structure and signature
          trust publisher <key>         trust a publisher's signing key (hex SPKI)
          trust peer <node-id>          allow a peer to connect to this node
          serve                         run a node: serve cached assets to authorized peers
          get <manifest>                fetch an asset: cache -> peers -> origin (all verified)
          cache list | cache remove <id> <version>
          peers                         listen for LAN peers and print what is found
          help [command]                show help

        Run 'xma help <command>' for command options.
        """;

    public static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            var (dataDir, rest) = ExtractGlobal(args);
            if (rest.Count == 0 || rest[0] is "help" or "--help" or "-h")
            {
                Console.WriteLine(rest.Count > 1 ? CommandHelp(rest[1]) : Help);
                return 0;
            }

            var cmd = rest[0];
            var tail = rest.Skip(1).ToList();
            return cmd switch
            {
                "init" => Init(dataDir),
                "publish" => await Publish(dataDir, tail, cts.Token),
                "verify" => Verify(tail),
                "trust" => Trust(dataDir, tail),
                "serve" => await Serve(dataDir, tail, cts.Token),
                "get" => await Get(dataDir, tail, cts.Token),
                "cache" => Cache(dataDir, tail),
                "peers" => await Peers(dataDir, tail, cts.Token),
                _ => throw new UsageException($"unknown command '{cmd}'. Try 'xma help'."),
            };
        }
        catch (UsageException ex) { Console.Error.WriteLine($"error: {ex.Message}"); return 64; }
        catch (XMeshException ex) { Console.Error.WriteLine($"error [{ex.Code}]: {ex.Message}"); return 2; }
        catch (OperationCanceledException) { Console.Error.WriteLine("cancelled."); return 130; }
        catch (FileNotFoundException ex) { Console.Error.WriteLine($"error: file not found: {ex.FileName}"); return 1; }
        catch (IOException ex) { Console.Error.WriteLine($"error: I/O failure: {ex.Message}"); return 1; }
    }

    /// <summary>--data-dir may appear before OR after the command; pull it out first.</summary>
    private static (string DataDir, List<string> Remaining) ExtractGlobal(string[] args)
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".xma");
        var rest = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a is "--data-dir" or "-d")
            {
                if (i + 1 >= args.Length) throw new UsageException("option --data-dir requires a value");
                dir = args[++i];
            }
            else if (a.StartsWith("--data-dir=", StringComparison.Ordinal)) dir = a["--data-dir=".Length..];
            else rest.Add(a);
        }
        return (Path.GetFullPath(dir), rest);
    }

    // ------------------------------------------------------------------ init
    private static int Init(string dir)
    {
        Directory.CreateDirectory(dir);
        using var id = NodeIdentity.LoadOrCreate(Path.Combine(dir, "identity.key"));
        Console.WriteLine($"node id     : {id.Id}");
        Console.WriteLine($"public key  : {Convert.ToHexString(id.PublicKeySpki).ToLowerInvariant()}");
        Console.WriteLine($"data dir    : {dir}");
        return 0;
    }

    // ------------------------------------------------------------------ publish
    private static readonly OptionSpec[] PublishSpecs =
    {
        new("id", null, true, "asset id (required)"),
        new("version", null, true, "asset version (required)"),
        new("publisher", null, true, "publisher display name (default: local)"),
        new("origin", null, true, "optional http(s) origin URL used as fallback"),
        new("chunk-size", null, true, $"bytes per chunk (default {ManifestBuilder.DefaultChunkSize})"),
        new("out", 'o', true, "manifest output path (default: <file>.xma.json)"),
    };

    private static async Task<int> Publish(string dir, List<string> args, CancellationToken ct)
    {
        var p = ArgParser.Parse(args, PublishSpecs);
        var file = new FileInfo(p.Positional(0, "file"));
        if (!file.Exists) throw new UsageException($"file not found: {file.FullName}");

        Directory.CreateDirectory(dir);
        using var identity = NodeIdentity.LoadOrCreate(Path.Combine(dir, "identity.key"));
        var keyHex = Convert.ToHexString(identity.PublicKeySpki).ToLowerInvariant();

        var unsigned = await ManifestBuilder.BuildAsync(file.FullName, p.Require("id"), p.Require("version"),
            p.Get("publisher") ?? "local", keyHex, p.Get("origin"),
            p.GetInt("chunk-size", ManifestBuilder.DefaultChunkSize), ct);
        var signed = ManifestSigner.Sign(unsigned, identity);

        var outPath = p.Get("out") ?? file.FullName + ".xma.json";
        File.WriteAllText(outPath, signed.ToJson());

        // Import the exact bytes we just hashed so this node can seed them immediately.
        var cache = new XMesh.Cache.AssetCache(Path.Combine(dir, "cache"), long.MaxValue);
        using (var session = cache.OpenSession(signed))
        {
            await using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.Asynchronous);
            var buf = new byte[signed.ChunkSize];
            for (int i = 0; i < signed.ChunkCount; i++)
            {
                int len = signed.ChunkLength(i);
                await fs.ReadExactlyAsync(buf.AsMemory(0, len), ct);
                await session.WriteChunkAsync(i, buf.AsMemory(0, len).ToArray(), ct); // verified against manifest on write
            }
            await session.FinalizeAsync(ct);
        }

        Console.WriteLine($"published   : {signed.AssetId}@{signed.Version}");
        Console.WriteLine($"size        : {signed.Size} bytes in {signed.ChunkCount} chunk(s) of {signed.ChunkSize}");
        Console.WriteLine($"root        : {signed.ComputeRoot()}");
        Console.WriteLine($"publisher   : {keyHex}");
        Console.WriteLine($"manifest    : {outPath}");
        Console.WriteLine();
        Console.WriteLine("on other nodes, trust this publisher first:");
        Console.WriteLine($"  xma trust publisher {keyHex}");
        return 0;
    }

    // ------------------------------------------------------------------ verify
    private static int Verify(List<string> args)
    {
        var p = ArgParser.Parse(args, Array.Empty<OptionSpec>());
        var m = AssetManifest.FromJson(File.ReadAllText(p.Positional(0, "manifest")));
        bool sig = ManifestSigner.VerifySignature(m);
        Console.WriteLine($"structure : ok ({m.ChunkCount} chunks, {m.Size} bytes)");
        Console.WriteLine($"signature : {(sig ? "VALID" : "INVALID")}");
        Console.WriteLine($"publisher : {m.Publisher}  key {m.PublisherKey}");
        Console.WriteLine($"root      : {m.ComputeRoot()}");
        return sig ? 0 : 3;
    }

    // ------------------------------------------------------------------ trust
    private static int Trust(string dir, List<string> args)
    {
        var p = ArgParser.Parse(args, Array.Empty<OptionSpec>());
        var what = p.Positional(0, "publisher|peer");
        var value = p.Positional(1, what == "peer" ? "node-id" : "key");
        Directory.CreateDirectory(dir);
        var store = new FileTrustStore(Path.Combine(dir, "trust.json"));
        switch (what)
        {
            case "publisher":
                if (!IsHex(value)) throw new UsageException("publisher key must be a hex string.");
                store.TrustPublisher(value); Console.WriteLine("publisher trusted."); return 0;
            case "peer":
                if (!IsHex(value) || value.Length != 64) throw new UsageException("node-id must be 64 hex characters.");
                store.AllowPeer(NodeId.Parse(value)); Console.WriteLine("peer allowed."); return 0;
            default: throw new UsageException("expected 'publisher' or 'peer'.");
        }
    }

    private static bool IsHex(string s) => s.Length > 0 && s.Length % 2 == 0 && s.All(Uri.IsHexDigit);

    // ------------------------------------------------------------------ serve
    private static readonly OptionSpec[] ServeSpecs =
    {
        new("port", null, true, "TCP port to listen on (default: auto)"),
        new("no-discovery", null, false, "do not broadcast/listen for LAN beacons"),
        new("open", null, false, "accept ANY authenticated peer (disables the allowlist)"),
    };

    private static async Task<int> Serve(string dir, List<string> args, CancellationToken ct)
    {
        var p = ArgParser.Parse(args, ServeSpecs);
        var opts = new XMeshOptions
        {
            DataDir = dir, ListenPort = p.GetInt("port", 0), EnableDiscovery = !p.Flag("no-discovery"),
            Policy = new XMeshPolicy { RequireAllowlist = !p.Flag("open") },
        };
        await using var rt = new XMeshRuntime(opts);
        rt.Log += m => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {m}");
        await rt.StartAsync();
        Console.WriteLine($"node id : {rt.Identity.Id}");
        Console.WriteLine($"listening on port {rt.ListenPort}{(p.Flag("open") ? " (OPEN: allowlist disabled)" : "")}. Ctrl+C to stop.");
        try { await Task.Delay(Timeout.Infinite, ct); } catch (OperationCanceledException) { }
        return 0;
    }

    // ------------------------------------------------------------------ get
    private static readonly OptionSpec[] GetSpecs =
    {
        new("peer", 'p', true, "static peer host:port (repeatable)"),
        new("no-peers", null, false, "skip peers; use cache and origin only"),
        new("no-origin", null, false, "never fall back to the origin"),
        new("no-discovery", null, false, "disable LAN discovery"),
        new("discover-seconds", null, true, "seconds to wait for LAN discovery (default 3)"),
        new("out", 'o', true, "copy the verified asset to this path"),
    };

    private static async Task<int> Get(string dir, List<string> args, CancellationToken ct)
    {
        var p = ArgParser.Parse(args, GetSpecs);
        var m = AssetManifest.FromJson(File.ReadAllText(p.Positional(0, "manifest")));
        var staticPeers = p.GetAll("peer");
        bool discover = !p.Flag("no-discovery") && !p.Flag("no-peers");

        var opts = new XMeshOptions
        {
            DataDir = dir, EnableServing = false, EnableDiscovery = discover, StaticPeers = staticPeers,
            // A downloading client initiates the connection, so it has no reason to require an inbound allowlist.
            Policy = new XMeshPolicy { RequireAllowlist = false },
        };
        await using var rt = new XMeshRuntime(opts);
        rt.Log += m => { if (m.Contains("skipped") || m.Contains("dropping")) Console.Error.WriteLine($"  note: {m}"); };
        await rt.StartAsync();

        int wait = p.GetInt("discover-seconds", 3);
        if (discover && wait > 0 && staticPeers.Count == 0)
        {
            Console.WriteLine($"discovering LAN peers for {wait}s...");
            await Task.Delay(TimeSpan.FromSeconds(wait), ct);
        }

        int lastDecile = -1;
        rt.Progress += pr =>
        {
            if (pr.State != TransferState.Transferring || pr.BytesTotal <= 0) return;
            int decile = (int)(pr.BytesDone * 10 / pr.BytesTotal);
            if (decile != lastDecile) { lastDecile = decile; Console.WriteLine($"  {decile * 10,3}%  via {pr.CurrentSource}"); }
        };

        var req = new AssetRequest(m.AssetId, m.Version) { AllowPeers = !p.Flag("no-peers"), AllowOrigin = !p.Flag("no-origin") };
        var r = await rt.GetAssetAsync(req, m, ct);

        Console.WriteLine($"done        : {r.AssetId}@{r.Version}  ({r.Size} bytes, verified={r.Verified})");
        Console.WriteLine($"from cache  : {r.BytesFromCache}");
        Console.WriteLine($"from peers  : {r.BytesFromPeers}");
        Console.WriteLine($"from origin : {r.BytesFromOrigin}");
        Console.WriteLine($"elapsed     : {r.Elapsed.TotalSeconds:F2}s");
        Console.WriteLine($"path        : {r.LocalPath}");
        if (p.Get("out") is { } o) { File.Copy(r.LocalPath, o, overwrite: true); Console.WriteLine($"copied to   : {o}"); }
        return 0;
    }

    // ------------------------------------------------------------------ cache
    private static int Cache(string dir, List<string> args)
    {
        var p = ArgParser.Parse(args, Array.Empty<OptionSpec>());
        var sub = p.Positional(0, "list|remove");
        var cache = new XMesh.Cache.AssetCache(Path.Combine(dir, "cache"), long.MaxValue);
        switch (sub)
        {
            case "list":
                var items = cache.List();
                if (items.Count == 0) { Console.WriteLine("(cache is empty)"); return 0; }
                foreach (var a in items)
                    Console.WriteLine($"{a.AssetId}@{a.Version}  {a.Size,14} bytes  {(a.Complete ? "complete" : "partial ")}  last used {a.LastAccessUtc:u}");
                return 0;
            case "remove":
                Console.WriteLine(cache.Delete(p.Positional(1, "asset-id"), p.Positional(2, "version")) ? "removed." : "not found.");
                return 0;
            default: throw new UsageException("expected 'list' or 'remove'.");
        }
    }

    // ------------------------------------------------------------------ peers
    private static async Task<int> Peers(string dir, List<string> args, CancellationToken ct)
    {
        var p = ArgParser.Parse(args, new[] { new OptionSpec("seconds", null, true, "how long to listen (default 5)") });
        await using var rt = new XMeshRuntime(new XMeshOptions { DataDir = dir, EnableServing = false, EnableDiscovery = true });
        await rt.StartAsync();
        await Task.Delay(TimeSpan.FromSeconds(p.GetInt("seconds", 5)), ct);
        var found = rt.DiscoveredPeers.Where(x => x.Port != 1).ToList();
        if (found.Count == 0) { Console.WriteLine("no peers found."); return 0; }
        foreach (var x in found) Console.WriteLine($"{x.Id}  {x.Address}:{x.Port}");
        return 0;
    }

    private static string CommandHelp(string cmd) => cmd switch
    {
        "publish" => ArgParser.Usage("publish", PublishSpecs, "<file> --id <id> --version <v>"),
        "serve" => ArgParser.Usage("serve", ServeSpecs),
        "get" => ArgParser.Usage("get", GetSpecs, "<manifest>"),
        "trust" => "usage: xma trust publisher <key-hex>\n       xma trust peer <node-id-hex>",
        "cache" => "usage: xma cache list\n       xma cache remove <asset-id> <version>",
        _ => Help,
    };
}
