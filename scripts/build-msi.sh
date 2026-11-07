#!/usr/bin/env bash
# Source lint of the Windows MSI on Linux/macOS.
#
# WiX v7 cannot BUILD an MSI off Windows: its binder loads msi.dll (verified in this repository's
# sandbox with the .NET 10 SDK: "Unable to load shared library 'msi.dll'"), and the compiler rejects
# every relative <Directory Name=...> on Linux (WIX0389). The real build is installer/windows/build.ps1
# on a Windows machine (CI job "msi" in .github/workflows/windows.yml).
#
# What this script still does is run the WiX compile and link phases over Package.wxs (with the
# LinuxLint define, which swaps only the directory declaration). That catches schema errors, unknown
# elements/attributes, bad references (custom actions, sequencing, extension elements). It reaches the
# bind phase and then stops at the missing msi.dll; that specific failure is the expected "lint OK".
#
#   scripts/build-msi.sh lint
#
# Needs the .NET SDK 8+ (apt: dotnet-sdk-10.0). It never signs anything.
set -euo pipefail

cd "$(dirname "$0")/.."
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

UTIL_EXT='WixToolset.Util.wixext/7.0.0'   # keep in step with .config/dotnet-tools.json (tested)
EULA='wix7'                               # project-recorded OSMF EULA acceptance (docs/DECISIONS.md D67)

cmd="${1:-lint}"
case "$cmd" in
  lint) ;;
  *)
    echo "usage: $0 lint" >&2
    echo "building the MSI needs Windows: run installer/windows/build.ps1 (see installer/windows/README.md)" >&2
    exit 2
    ;;
esac

command -v dotnet >/dev/null || { echo "dotnet SDK not found" >&2; exit 2; }
dotnet tool restore >/dev/null
dotnet wix --acceptEula "$EULA" extension add -g "$UTIL_EXT" >/dev/null 2>&1

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'MZ' >"$work/librepatch-agent.exe"

# The product name comes from internal/shared/brand (the same source as the server and the web console).
brand_defs=()
while IFS= read -r kv; do brand_defs+=(-d "$kv"); done < <(go run ./internal/shared/brand/gen -wix)

set +e
out="$(dotnet wix --acceptEula "$EULA" build -arch x64 -ext "${UTIL_EXT%%/*}" \
  "${brand_defs[@]}" -d LinuxLint=1 -d Version=0.1.0.0 -d "AgentExe=$work/librepatch-agent.exe" \
  -o "$work/lint.msi" installer/windows/Package.wxs 2>&1)"
rc=$?
set -e

# Drop the "WiX only supports Windows" banner that every invocation prints on Linux.
out="$(printf '%s\n' "$out" | grep -v 'The WiX Toolset only supports Windows' || true)"

if [ "$rc" -eq 0 ]; then
  echo "lint OK (unexpected: the build completed)"
  exit 0
fi
# The expected end state is exactly one error: the binder failing to load msi.dll (WIX0001).
other="$(printf '%s\n' "$out" | grep -E 'error WIX[0-9]+:' | grep -v 'WIX0001: System.DllNotFoundException' || true)"
if [ -n "$other" ] || ! printf '%s\n' "$out" | grep -q "Unable to load shared library 'msi.dll'"; then
  printf '%s\n' "$out" | cut -c1-400 | head -30 >&2
  echo "lint FAILED" >&2
  exit 1
fi
echo "lint OK: WiX v7 compile and link of installer/windows/Package.wxs passed (the MSI bind step needs Windows)."
