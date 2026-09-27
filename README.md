# X-Mesh Agent Engine (XMA), Phase 1

A cross-platform-friendly **distributed asset delivery runtime**. An application asks for an
asset; XMA delivers it from the cheapest trustworthy source:

```
local cache  ->  LAN / static peers  ->  HTTP origin (fallback)
```

Every chunk from every source is **SHA-256 verified against a publisher-signed manifest**
before it is ever written to the cache. Peers and origins are treated as *untrusted transport*.

This is **Phase 1** of the roadmap (spec sections 51 and 57): the smallest thing that is actually
useful and actually secure. It deliberately does *not* include WAN/NAT traversal, QUIC, a
scheduler, or non-.NET SDKs (see "Not in Phase 1").

## What is in Phase 1

| Capability | Where |
|---|---|
| Node identity (ECDSA P-256, `NodeId = SHA-256(SPKI)`) | `XMesh.Security/NodeIdentity.cs` |
| Signed, versioned manifests with strict validation | `XMesh.Assets/AssetManifest.cs` |
| Streaming chunker + constant-time chunk verification | `XMesh.Assets/ManifestBuilder.cs` |
| Resumable, crash-safe, verified cache with LRU eviction | `XMesh.Cache/AssetCache.cs` |
| Bounded wire framing + strict message codec | `XMesh.Protocol/` |
| Mutual challenge-response handshake (replay/reflection safe) | `XMesh.Security/Handshake.cs` |
| TLS 1.3 encrypted TCP transport, connection caps, timeouts | `XMesh.Transport/` |
| Peer allowlist (authentication is not authorization) | `XMesh.Security/TrustStore.cs` |
| LAN discovery (UDP beacons, unauthenticated hints) | `XMesh.Discovery/LanDiscovery.cs` |
| HTTP Range origin fallback | `XMesh.Transport/OriginClient.cs` |
| Runtime: source ordering, resume, request de-dup, poisoned-peer dropping | `XMesh.Runtime/XMeshRuntime.cs` |
| `xma` CLI | `XMesh.Cli/` |

## Build and test

Requires only the **.NET 10 SDK**. There are **zero NuGet dependencies**, so this builds fully offline.

```bash
./build.sh            # restore + build + test + portable publish (out/xma)
# or manually:
dotnet build -c Release
dotnet run -c Release --project tests/XMesh.Tests
```

The test project is a self-contained console runner (see `tests/XMesh.Tests/MiniXunit.cs`); it uses
xunit's attribute/assert names so the tests port to real xunit unchanged.

## Quick start

```bash
# Machine A: publish a file and serve it
xma init
xma publish ./game-patch.bin --id game-patch --version 1.2.0 --origin https://cdn.example.com/game-patch.bin
xma serve --port 7000

# Machine B: trust A's publisher key, allow-list nothing (client only), fetch
xma trust publisher <publisher-key-printed-by-publish>
xma get ./game-patch.bin.xma.json --peer 192.168.1.10:7000 -o ./game-patch.bin

# A must allow B to connect (authorization is separate from authentication):
xma trust peer <B's node id>
```

`xma get` prints how many bytes came from cache / peers / origin, so you can see the
delivery path.

## Running on Android / Termux (read before trying)

The build is a **portable, architecture-neutral** set of managed `.dll` files (`xma-portable` CI
artifact, or `out/xma/` from `./build.sh`). It contains no native code, so the *files* run on any CPU.
What it needs is a **.NET 10 runtime on the device**:

```
dotnet xma.dll init
dotnet xma.dll get game-patch.bin.xma.json --peer 192.168.1.10:7000
```

**Do not use the `linux-arm64` self-contained CI artifacts on a phone.** They target glibc; Android
and Termux use Bionic libc, and upstream glibc `linux-arm64` .NET builds are reported to fail there
(missing `libdl.so.2`, TLS-alignment errors in the native launcher). Microsoft lists a separate
`linux-bionic-arm64` RID (Termux is the named example), but documents Bionic publishing as NativeAOT-only,
which this project does not use. The portable artifact sidesteps all of that.

**Status: NOT tested on Android.** Whether a Bionic-native .NET 10 runtime is available to you in
Termux (package availability changes) and whether XMA runs on it has not been verified. Two
Android-specific risks worth knowing:

- **LAN discovery** relies on UDP broadcast; Android may restrict or power-manage it. Use `--peer host:port`
  as the dependable path.
- **Background serving**: Android can kill a backgrounded Termux process. Use a wake lock (`termux-wake-lock`).

If the runtime is unavailable, the pragmatic alternative is to run XMA on a PC/server/Raspberry Pi and
treat the phone as a client of it.

## Security model (read this)

- **Chunk integrity != publisher authenticity.** A matching chunk hash proves the bytes match the
  manifest, not that the manifest is legitimate. Manifests are ECDSA-signed, and the signing key
  must be in the local trusted-publisher set (`xma trust publisher`), or the request is refused
  before any network activity.
- **Encryption and identity are separate layers.** The channel is TLS 1.3 with an ephemeral
  self-signed certificate (confidentiality only; the certificate is intentionally *not* trusted).
  Identity is proven inside the channel by the XMA handshake.
- **Handshake** binds both nonces, both public keys and the role into every signature, so a proof
  cannot be replayed into another session, reflected back, or redirected to a different peer.
- **Authorization** is a separate allowlist gate applied after authentication; default is restrictive.
- **Discovery is a hint, never trust.** A spoofed beacon can cost one connection attempt; it cannot
  impersonate a node or inject data.
- **All parsers are bounded**: frame length is checked before allocation; every field length is
  range-checked; malformed input raises `ProtocolViolation`, never a crash or unbounded allocation.
- **Path safety**: asset ids/versions are restricted to `[A-Za-z0-9._-]` and re-checked at the
  cache boundary to make traversal impossible.

## Honest limitations

- Compiled and tested on **linux-x64 only** (.NET 10.0.302). Windows, macOS and ARM are untested; see `docs/STATUS.md`.
- No third-party security review. Do not use to distribute high-risk assets without one.
- Transport is TCP+TLS. QUIC is a later phase.
- The manifest uses a flat chunk-hash list, not a Merkle tree, so partial verification of a chunk
  *stream* is not possible (whole chunks are verified).
- Discovery is IPv4 UDP broadcast only.

## Not in Phase 1 (by design)

WAN peer-to-peer and NAT traversal, QUIC, multi-source scheduler/rebalancing, relay nodes, mobile
and game-engine SDKs (Kotlin/Swift/TypeScript/Unity/Godot), and web support. These are Phase 3+ in
the spec and each is a project of its own.
