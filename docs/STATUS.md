# Project status

## Verified (compiled and executed)

Built and tested with **.NET SDK 10.0.302 (runtime 10.0.10), linux-x64**, fully offline (zero NuGet packages).

| Check | Result |
|---|---|
| Clean build, `-p:StrictWarnings=true` (warnings as errors) | 0 errors, 0 warnings |
| Test suite | 64 / 64 pass |
| Repeated-run flake hunt | 60 consecutive full runs (3,840 test executions), 0 failures |
| Multi-process CLI run (separate `xma serve` / `xma get` processes, real TCP + TLS 1.3) | verified below |

Multi-process scenarios run against the published `xma` binary:

1. Peer **not** on the allowlist is refused with an actionable message; nothing is cached.
2. After `xma trust peer <id>`, a 3 MB asset transfers and is **byte-identical** (SHA-256 compared).
3. Second request is served purely from cache with the server stopped.
4. A tampered manifest (`version` edited) fails signature verification (exit 3).
5. A server whose on-disk chunk was silently corrupted is caught; the download **fails closed** and
   nothing is marked complete.

## Defects found by actually running it (all fixed, all covered by tests)

| # | Defect | How it was found |
|---|---|---|
| 1 | `AssetManifest.IsSafeToken` was `internal`, used across assemblies | compiler |
| 2 | Tuple element named `Rest` is reserved | compiler |
| 3 | TLS callback set twice (`SslStream` ctor and options) - **every peer connection threw** | end-to-end tests |
| 4 | One misbehaving peer could abort the whole transfer instead of just being skipped | end-to-end tests |
| 5 | `DisposeAsync` not idempotent (double-dispose threw) | end-to-end tests |
| 6 | In-flight de-dup race: a failed transfer's stale task could be returned to an immediate retry | 14/30 isolated-run failure rate |
| 7 | LRU used filesystem atime, which is unreliable (`noatime`/`relatime`); eviction order was wrong | LRU test |
| 8 | `WriteAtomic` shared one temp filename across threads: ~19% of concurrent writes failed | 1-in-25 flaky test, then isolated reproduction |
| 9 | Allowlist refusal surfaced as "Broken pipe" instead of a clear reason | CLI run |

Item 8's regression test was validated by **reintroducing the bug**: the test fails 6/10 runs with
the bug, 0/30 without. (A first version of that test passed even with the bug present; it was
strengthened before being trusted.)

## Correction recorded during packaging

An earlier iteration of the CI workflow presented `linux-arm64` self-contained builds as the route to
a phone. That was wrong for Android/Termux (Bionic vs glibc). CI now labels those artifacts glibc-only
and adds `xma-portable` (no native files; verified by scanning the output for ELF binaries).

## Not verified / known limits

- **Android/Termux: untested.** See the README section for what is and is not known.

- **Only linux-x64 was exercised.** Windows, macOS and ARM (including Android/Termux) have not been run.
  CI (`.github/workflows/ci.yml`) is set up to build and test on ubuntu, windows and macos.
- Tested only on loopback. No real multi-host LAN, packet loss, NAT, or hostile-network testing.
- LAN discovery is verified on loopback only (two nodes, one host).
- No performance or scale testing beyond ~3 MB / a few hundred chunks.
- No independent security review. Do not use to distribute high-risk assets without one.
- Trust files are read at startup; adding a peer requires restarting `xma serve`.
- Transport is TCP+TLS. No QUIC, no WAN/NAT traversal, no scheduler, no non-.NET SDKs (later phases).
