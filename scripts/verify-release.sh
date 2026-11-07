#!/usr/bin/env bash
# Verifies a downloaded LibrePatch release directory (docs/VERIFYING_RELEASES.md explains every check).
#
#   scripts/verify-release.sh --dir DIR --repo auzring1/librepatch --tag v1.2.3 --pub <hex>[,<hex>]
#
# Checks, in this order; any failure makes the exit status 1:
#   1. SHA256SUMS: every listed file matches (and files that are not listed are reported)
#   2. cosign: SHA256SUMS.sigstore.json is a keyless signature by this repository's release workflow at the tag
#   3. cosign: each <artifact>.sbom.sigstore.json is a CycloneDX attestation for that artifact by the same workflow
#   4. GitHub build provenance (SLSA) of the main artifacts: `gh attestation verify`
#   5. The vendor release bundle (.lprel): Ed25519 signature under the vendor key you supply, and it matches the agent exe
#   6. Every *.cdx.json is a CycloneDX 1.5 document (shape only)
#   7. Authenticode of the agent and the MSI, when --authenticode-subject is given and Windows tooling is present
#
# Options
#   --dir DIR                   the release directory (default .)
#   --repo OWNER/REPO           GitHub repository that built it (needed for 2-4)
#   --tag vX.Y.Z                exact tag to expect in the signing identity (default: any v* tag of the repo)
#   --pub HEX[,HEX]             vendor release public key(s), hex; from your own records, NOT from the release directory
#   --pub-file FILE             same, from a file (lines starting with # are ignored)
#   --release-tool PATH         librepatch-release binary to use (default: the one in DIR on linux/amd64)
#   --authenticode-subject CN   expected Authenticode signer (the CN pinned in the vendor manifest)
#   --skip-cosign, --skip-attestations   skip 2-3 / 4 (used by the pipeline before anything is signed)
#   --skip-curr                  skip 5 (no vendor key at hand)
#
# Requires: sha256sum, jq; cosign for 2-3; gh (logged in) for 4. Nothing is installed or downloaded by this script.
set -uo pipefail

dir=. repo="" tag="" pubs="" pubfile="" tool="" subject=""
skip_cosign=0 skip_att=0 skip_curr=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir=${2:?}; shift 2 ;;
    --repo) repo=${2:?}; shift 2 ;;
    --tag) tag=${2:?}; shift 2 ;;
    --pub) pubs=${2:?}; shift 2 ;;
    --pub-file) pubfile=${2:?}; shift 2 ;;
    --release-tool) tool=${2:?}; shift 2 ;;
    --authenticode-subject) subject=${2:?}; shift 2 ;;
    --skip-cosign) skip_cosign=1; shift ;;
    --skip-attestations) skip_att=1; shift ;;
    --skip-curr) skip_curr=1; shift ;;
    -h|--help) sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

fails=0
ok()   { printf 'PASS  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }

cd "$dir" || { echo "cannot enter $dir" >&2; exit 2; }
command -v sha256sum >/dev/null && command -v jq >/dev/null || { echo "sha256sum and jq are required" >&2; exit 2; }

# ---- 1. checksums ----------------------------------------------------------------------------------
if [ ! -f SHA256SUMS ]; then
  fail "SHA256SUMS is missing"
else
  if out=$(sha256sum -c SHA256SUMS 2>&1); then ok "SHA256SUMS: $(wc -l <SHA256SUMS) files match"; else fail "SHA256SUMS: $(printf '%s\n' "$out" | grep -v ': OK$' | head -5 | tr '\n' ' ')"; fi
  for f in *; do
    [ -f "$f" ] || continue
    case "$f" in SHA256SUMS|SHA256SUMS.*|*.sigstore.json) continue ;; esac
    grep -q "  $f\$" SHA256SUMS || warn "$f is not listed in SHA256SUMS"
  done
fi

# ---- 2-3. cosign -----------------------------------------------------------------------------------
issuer=https://token.actions.githubusercontent.com
id_args=()
if [ -n "$repo" ]; then
  if [ -n "$tag" ]; then
    id_args=(--certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag")
  else
    id_args=(--certificate-identity-regexp "^https://github\\.com/${repo//./\\.}/\\.github/workflows/release\\.yml@refs/tags/v")
  fi
  id_args+=(--certificate-oidc-issuer "$issuer")
fi
if [ "$skip_cosign" = 1 ]; then
  warn "cosign checks skipped"
elif [ -z "$repo" ]; then
  fail "--repo is required for the cosign checks (or pass --skip-cosign)"
elif ! command -v cosign >/dev/null; then
  fail "cosign is not installed (https://docs.sigstore.dev/); install it or pass --skip-cosign"
else
  if cosign verify-blob --bundle SHA256SUMS.sigstore.json "${id_args[@]}" SHA256SUMS >/dev/null 2>&1; then
    ok "cosign: SHA256SUMS was signed by the $repo release workflow${tag:+ at $tag}"
  else
    fail "cosign: SHA256SUMS.sigstore.json does not verify for $repo${tag:+ at $tag}"
  fi
  shopt -s nullglob
  for b in *.sbom.sigstore.json; do
    subj=${b%.sbom.sigstore.json}
    if [ -f "$subj" ] && cosign verify-blob-attestation --bundle "$b" --type cyclonedx "${id_args[@]}" "$subj" >/dev/null 2>&1; then
      ok "cosign: SBOM attestation for $subj"
    else
      fail "cosign: SBOM attestation $b does not verify for $subj"
    fi
  done
  shopt -u nullglob
fi

# ---- 4. provenance -----------------------------------------------------------------------------------
if [ "$skip_att" = 1 ]; then
  warn "provenance checks skipped"
elif [ -z "$repo" ]; then
  fail "--repo is required for the provenance check (or pass --skip-attestations)"
elif ! command -v gh >/dev/null; then
  fail "gh (GitHub CLI) is not installed; install it or pass --skip-attestations"
else
  shopt -s nullglob
  for f in librepatch-agent_*.exe librepatch-agent_*.msi librepatch-server_*_linux_amd64 librepatch-release_*_linux_amd64 librepatch-web_*.tar.gz; do
    if gh attestation verify "$f" --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml" >/dev/null 2>&1; then
      ok "provenance: $f was built by the $repo release workflow"
    else
      fail "provenance: no valid attestation for $f"
    fi
  done
  shopt -u nullglob
fi

# ---- 5. vendor release bundle ---------------------------------------------------------------------
shopt -s nullglob
rnrs=(librepatch-agent_*.lprel)
shopt -u nullglob
if [ "$skip_curr" = 1 ]; then
  warn "vendor bundle check skipped"
elif [ ${#rnrs[@]} -eq 0 ]; then
  fail "no librepatch-agent_*.lprel vendor release bundle in the directory"
else
  keyfile=$(mktemp)
  trap 'rm -f "$keyfile"' EXIT
  { [ -z "$pubs" ] || echo "$pubs"; [ -z "$pubfile" ] || grep -Ev '^[[:space:]]*(#|$)' "$pubfile"; } | tr -d '[:space:]' >"$keyfile"
  if [ ! -s "$keyfile" ]; then
    fail "the vendor bundle cannot be verified without the vendor public key (--pub or --pub-file; take it from your own records)"
  else
    if [ -z "$tool" ]; then
      for t in librepatch-release_*_linux_amd64; do [ -f "$t" ] && tool="$PWD/$t"; done
    fi
    if [ -z "$tool" ] || [ ! -f "$tool" ]; then
      fail "no librepatch-release tool (build it from source with go build ./cmd/librepatch-release, or pass --release-tool)"
    else
      [ -x "$tool" ] || chmod +x "$tool" 2>/dev/null || true
      for rnr in "${rnrs[@]}"; do
        exe=${rnr%.lprel}.exe
        if out=$("$tool" verify --bundle "$rnr" --exe "$exe" --pub "$keyfile" 2>&1); then ok "vendor bundle: $out"; else fail "vendor bundle $rnr: $out"; fi
      done
    fi
  fi
fi

# ---- 6. SBOM shape ---------------------------------------------------------------------------------
shopt -s nullglob
for s in *.cdx.json; do
  if jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5" and (.components | length) > 0 and (.metadata.component.name | length) > 0' "$s" >/dev/null 2>&1; then
    ok "SBOM: $s is CycloneDX 1.5 with $(jq '.components | length' "$s") components"
  else
    fail "SBOM: $s is not a CycloneDX 1.5 document"
  fi
done
shopt -u nullglob

# ---- 7. Authenticode -------------------------------------------------------------------------------
if [ -n "$subject" ]; then
  shopt -s nullglob
  pes=(librepatch-agent_*.exe librepatch-agent_*.msi)
  shopt -u nullglob
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  if command -v pwsh >/dev/null && [ "$(uname -s | cut -c1-5)" != Linux ]; then
    for f in "${pes[@]}"; do
      if pwsh -NoProfile -File "$here/authenticode.ps1" -Action Verify -Subject "$subject" -Files "$f" >/dev/null 2>&1; then ok "Authenticode: $f signed by '$subject'"; else fail "Authenticode: $f"; fi
    done
  else
    warn "Authenticode NOT CHECKED on this platform: on Windows run  Get-AuthenticodeSignature <file>  and compare the signer CN to '$subject' (docs/VERIFYING_RELEASES.md)"
  fi
fi

echo
if [ "$fails" -eq 0 ]; then echo "verify-release: all checks passed"; else echo "verify-release: $fails check(s) FAILED"; exit 1; fi
