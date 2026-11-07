#!/usr/bin/env bash
# Fails if any shipped dependency is not under an allow-listed permissive
# license (docs/DECISIONS.md O1: closed source, no GPL/AGPL).
set -euo pipefail
cd "$(dirname "$0")/.."
allowed_go="Apache-2.0,BSD-2-Clause,BSD-3-Clause,MIT,ISC,MPL-2.0"
echo "== Go modules linked into shipped binaries"
for goos in linux windows; do
  GOOS=$goos go-licenses check ./cmd/... --allowed_licenses="$allowed_go" \
    --ignore github.com/auzring1/librepatch
done
echo "== npm production dependencies (web console bundle)"
node - <<'JS'
const lock = require("./web/package-lock.json");
const allowed = new Set(["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "MPL-2.0"]);
let bad = 0;
for (const [path, pkg] of Object.entries(lock.packages)) {
  if (!path || pkg.dev) continue;
  const lic = pkg.license ?? "UNKNOWN";
  // The bundled Inter typeface is the one exception: SIL OFL-1.1 permits bundling a font unmodified (decision D93).
  if (path === "node_modules/@fontsource-variable/inter" && lic === "OFL-1.1") continue;
  const ok = lic.replace(/[()]/g, "").split(/\s+OR\s+/).some((l) => allowed.has(l.trim()));
  if (!ok) { console.error(`disallowed license ${lic}: ${path}`); bad++; }
}
if (bad) process.exit(1);
console.log("npm production licenses OK");
JS
