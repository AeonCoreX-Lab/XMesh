# XMA Phase 1: Architecture

## Layering (dependency direction is strictly downward)

```
XMesh.Cli
   |
XMesh.Runtime          orchestration: source order, resume, de-dup, poisoned-peer handling
   |        \
XMesh.Transport   XMesh.Discovery       TLS/TCP peer session+server+client, HTTP origin | LAN beacons
   |
XMesh.Security   XMesh.Cache            identity, handshake, signing, trust | verified resumable store
   |                 |
XMesh.Protocol   XMesh.Assets           framing + messages | manifest, chunking, verification
        \          /
        XMesh.Core                      NodeId, policy, error codes, transfer states
```

No project references a project above it (checked mechanically: no cycles, every `using XMesh.*`
resolves to a reachable project reference).

## Delivery path (`XMeshRuntime.GetAssetAsync`)

1. **Resolve**: manifest must match the requested id/version; signature verified; publisher must be trusted.
2. **Cache**: if the verified asset is already present, return it (works fully offline).
3. **Resume**: chunks already verified on disk from a previous attempt count as cache hits.
4. **Peers**: connect to static + LAN-discovered peers in parallel. For each peer: TLS, handshake,
   allowlist, confirm it holds the *same manifest root*, then pull missing chunks.
   - A chunk a peer lacks is returned to the queue for other peers.
   - A slow/failed peer's in-flight chunk is returned to the queue.
   - A peer that sends bytes failing verification is dropped for the rest of the transfer.
5. **Origin**: whatever is still missing is fetched via HTTP Range, with retry and back-off.
6. **Finalize**: every chunk re-verified from disk, atomic rename to `data.bin`, `complete` marker written.
7. **Evict**: LRU eviction of *other* complete assets if over the cache budget.

Concurrent requests for the same `asset@version` share one transfer.

## Cache layout and crash safety

```
{cache}/{assetId}/{version}/manifest.json
                           /data.part      sparse file written at chunk offsets (RandomAccess)
                           /state.json     bitmap of VERIFIED chunks (+ manifest root)
                           /data.bin       final file, present only after full re-verification
                           /complete       marker (contains the manifest root)
```

A chunk is marked done only after it passed SHA-256 verification, and `state.json` is written
atomically (temp + rename). A crash can lose progress but can never yield an unverified "complete" asset.
`state.json` is bound to the manifest root, so a changed manifest invalidates stale progress.

## Wire format

Frame: `"XMA1"(4) | type(1) | length u32 big-endian (4) | payload`. Max payload = 16 MiB + 4 KiB.
Strings/blobs are `int32 length | bytes`. The framing and the signing-bytes layouts are pinned by
test vectors generated from an independent Python reference (`tests/XMesh.Tests/WireVectorTests.cs`).

Message types: Hello, Challenge, Auth, AuthOk, GetManifest, Manifest, Have, GetChunk, Chunk,
NotFound, Error, Bye. (`Have` is reserved; Phase 1 does not send it.)

## Handshake

```
both:  Hello{version, SPKI, canServe}        (protocol version must match)
both:  Challenge{nonce32}
both:  Auth{ ECDSA-P256-SHA256( "XMA-AUTH-V1" | role | nonceInit | nonceResp | lp(signerSPKI) | lp(peerSPKI) ) }
then:  allowlist check on NodeId(peer)       (authorization, after authentication)
both:  AuthOk  |  Error("not authorized")     (explicit verdict, so a refusal is reported clearly)
```
