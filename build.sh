#!/usr/bin/env bash
# Build, test and publish XMA. Requires the .NET 10 SDK on PATH. Zero NuGet dependencies, so the
# build and test steps work fully offline.
#
#   ./build.sh                 build + test + framework-dependent publish  (works offline)
#   SELF_CONTAINED=1 ./build.sh   also produce a single-file, self-contained binary
#                                 (needs internet once: it downloads the .NET runtime pack from NuGet)
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet not found. Install the .NET 10 SDK, or extract the tarball and:" >&2
  echo "  export DOTNET_ROOT=\$HOME/dotnet PATH=\$PATH:\$HOME/dotnet" >&2
  exit 1
fi

export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
echo "== dotnet $(dotnet --version)"

echo "== build (warnings as errors)"
dotnet build -c Release -p:StrictWarnings=true

echo "== test"
dotnet run -c Release --no-build --project tests/XMesh.Tests

echo "== publish (portable, architecture-neutral; run with: dotnet out/xma/xma.dll <command>)"
# UseAppHost=false: no native launcher is emitted, so the output has no CPU/libc-specific files at all.
dotnet publish src/XMesh.Cli -c Release -p:UseAppHost=false -o out/xma
echo "   -> out/xma/xma.dll"

if [[ "${SELF_CONTAINED:-0}" == "1" ]]; then
  RID="${RID:-$(dotnet --info | awk '/RID:/{print $2; exit}')}"
  echo "== publish self-contained single file for $RID (downloads runtime pack)"
  dotnet publish src/XMesh.Cli -c Release -r "$RID" --self-contained \
    -p:PublishSingleFile=true -o "out/$RID"
  echo "   -> out/$RID/xma"
fi
echo "== done"
