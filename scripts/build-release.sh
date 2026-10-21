#!/usr/bin/env bash
# Reproducible release build (docs/PLAN.md Phase 6, docs/DECISIONS.md D79-D82, docs/VERIFYING_RELEASES.md).
#
#   scripts/build-release.sh --version 1.2.3 [--out DIR] [--release-pubkeys HEX[,HEX...]] [options]
#
# From a clean checkout of one commit this produces, byte for byte the same on any machine with the same
# pinned toolchains (Go from go.mod's `toolchain` line, Node major 22, web/package-lock.json):
#
#   librepatch-agent_<v>_windows_amd64.exe      the agent (UNSIGNED: Authenticode is applied later by release.yml)
#   librepatch-server_<v>_linux_amd64           the server with the web console embedded
#   librepatch-release_<v>_linux_amd64          vendor tool (manifest / sign / verify)
#   librepatch-web_<v>.tar.gz                   the web console bundle (what is embedded in the server)
#   *.cdx.json                               CycloneDX 1.5 SBOMs, one per binary and one for the web bundle
#   unsigned-SHA256SUMS                      digests of everything above (this is what a rebuild must match)
#   BUILD-INFO.txt                           inputs: commit, SOURCE_DATE_EPOCH, toolchains, ldflags
#
# What makes it reproducible: -trimpath, -buildvcs=false, an empty linker build id, CGO_ENABLED=0,
# -mod=readonly, GOTOOLCHAIN pinned to go.mod, a fixed ldflags set, TZ=UTC / LC_ALL=C, SOURCE_DATE_EPOCH taken
# from the commit time (used for SBOM timestamps and archive mtimes), `npm ci --ignore-scripts` from the lockfile,
# and sorted, owner-less, fixed-mtime archives.
#
# Options:
#   --version V              release version, 1.2.3 or v1.2.3 or 1.2.3-rc.1 (required; "v" is stripped for embedding)
#   --commit REV             must resolve to HEAD (default HEAD); the tree must be clean unless --allow-dirty
#   --out DIR                output directory (default dist-release/<version>; must be empty or absent)
#   --release-pubkeys LIST   comma-separated vendor release public keys (hex). Default: $LIBREPATCH_RELEASE_PUBKEYS, else the
#                            non-comment lines of release/release-public-keys.txt. No key = refuse (see --allow-no-release-key)
#   --allow-no-release-key   build without any compiled-in release key (agents then refuse all updates; development only)
#   --require-authenticode B true (default, release) or false: sets release.RequireAuthenticode
#   --authenticode-subjects L "|"-separated signer CNs compiled into agent and server as the only subjects a release
#                            may pin (default: $LIBREPATCH_AUTHENTICODE_SUBJECTS). Required when --require-authenticode is true,
#                            unless --allow-no-subject-pin: otherwise a stolen release key could pin any certificate (D83)
#   --allow-no-subject-pin   development/rehearsal builds only
#   --with-arm64             also build the windows/arm64 agent (builds, but is unsupported and untested; MSI is x64 only)
#   --skip-web               do not build the web bundle (server then embeds no console; tests only)
#   --skip-sbom              do not write SBOMs
#   --image                  also build the container image as an OCI archive (needs Docker/BuildKit; scripts/build-image.sh)
#   --allow-dirty            build a dirty tree (never for releases)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD

NODE_MAJOR=22          # keep in step with .github/workflows/ci.yml NODE_VERSION and deploy/Dockerfile.server
AGENT_MAX_BYTES=17825792

die() { echo "build-release: $*" >&2; exit 1; }

version="" commit="HEAD" out="" pubkeys="${LIBREPATCH_RELEASE_PUBKEYS:-}" allow_no_key=0 req_auth=true
subjects="${LIBREPATCH_AUTHENTICODE_SUBJECTS:-}" allow_no_pin=0
with_arm64=0 skip_web=0 skip_sbom=0 want_image=0 allow_dirty=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=${2:?}; shift 2 ;;
    --commit) commit=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --release-pubkeys) pubkeys=${2:?}; shift 2 ;;
    --allow-no-release-key) allow_no_key=1; shift ;;
    --require-authenticode) req_auth=${2:?}; shift 2 ;;
    --authenticode-subjects) subjects=${2:?}; shift 2 ;;
    --allow-no-subject-pin) allow_no_pin=1; shift ;;
    --with-arm64) with_arm64=1; shift ;;
    --skip-web) skip_web=1; shift ;;
    --skip-sbom) skip_sbom=1; shift ;;
    --image) want_image=1; shift ;;
    --allow-dirty) allow_dirty=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[ -n "$version" ] || die "--version is required"
version_re='^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$'
[[ $version =~ $version_re ]] || die "version '$version' is not semantic (1.2.3, v1.2.3, 1.2.3-rc.1)"
v=${version#v}
case "$req_auth" in true|false) ;; *) die "--require-authenticode must be true or false" ;; esac

# --- source: one commit, clean tree ----------------------------------------------------------------
full=$(git rev-parse --verify "${commit}^{commit}") || die "unknown commit $commit"
[ "$full" = "$(git rev-parse HEAD)" ] || die "--commit must be the checked-out HEAD (the build uses the working tree)"
if [ "$allow_dirty" = 0 ] && [ -n "$(git status --porcelain)" ]; then
  die "the working tree is not clean (commit or stash, or pass --allow-dirty for a non-release build)"
fi
short=${full:0:12}
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$full")
export SOURCE_DATE_EPOCH

# --- release keys ----------------------------------------------------------------------------------
if [ -z "$pubkeys" ] && [ -f release/release-public-keys.txt ]; then
  pubkeys=$(grep -Ev '^[[:space:]]*(#|$)' release/release-public-keys.txt | tr -d '[:space:]' | paste -sd, - || true)
fi
if [ -n "$pubkeys" ]; then
  IFS=, read -ra _keys <<<"$pubkeys"
  for k in "${_keys[@]}"; do
    [[ $k =~ ^[0-9a-f]{64}$ ]] || die "release public key '${k:0:16}...' is not 64 lowercase hex characters"
  done
elif [ "$allow_no_key" = 0 ]; then
  die "no vendor release public key: pass --release-pubkeys, set LIBREPATCH_RELEASE_PUBKEYS or add one to release/release-public-keys.txt (docs/RUNBOOK.md, release manager)"
fi

if [ -n "$subjects" ]; then
  case "$subjects" in *\'*|*\"*|*\\*|*$'\n'*) die "--authenticode-subjects must not contain quotes, backslashes or newlines" ;; esac
elif [ "$req_auth" = true ] && [ "$allow_no_pin" = 0 ]; then
  die "no compiled-in Authenticode subject: pass --authenticode-subjects \"<signer CN>\" (or LIBREPATCH_AUTHENTICODE_SUBJECTS); see docs/DECISIONS.md D83"
fi

# --- toolchains ------------------------------------------------------------------------------------
want_go=$(awk '$1=="toolchain"{print $2}' go.mod)
[ -n "$want_go" ] || want_go="go$(awk '$1=="go"{print $2}' go.mod)"
export GOTOOLCHAIN="${GOTOOLCHAIN:-$want_go}"
have_go=$(go env GOVERSION)
[ "$have_go" = "$want_go" ] || die "Go toolchain is $have_go but go.mod pins $want_go (set GOTOOLCHAIN=$want_go)"
if [ "$skip_web" = 0 ]; then
  command -v node >/dev/null && command -v npm >/dev/null || die "node and npm are required (or --skip-web)"
  have_node=$(node --version)
  [ "$(echo "${have_node#v}" | cut -d. -f1)" = "$NODE_MAJOR" ] || die "Node $have_node found, the release build is pinned to Node $NODE_MAJOR.x"
fi

# --- environment that must not leak into the output --------------------------------------------------
unset GOFLAGS GOEXPERIMENT GOAMD64 GOARM64 GOARM GO386 CGO_CFLAGS CGO_LDFLAGS GOWORK GOOS GOARCH
export CGO_ENABLED=0 GOFLAGS=-mod=readonly GOWORK=off TZ=UTC LC_ALL=C

[ -n "$out" ] || out="$ROOT/dist-release/$v"
mkdir -p "$out"
out=$(cd "$out" && pwd)
if [ -n "$(ls -A "$out")" ]; then die "output directory $out is not empty"; fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pkg=github.com/auzring1/librepatch/internal/shared
ldflags="-s -w -buildid= -X $pkg/version.Version=$v -X $pkg/version.Commit=$short"
ldflags="$ldflags -X $pkg/release.PublicKeysHex=$pubkeys -X $pkg/release.RequireAuthenticode=$req_auth"
# the subject list may contain spaces: single-quote the whole -X argument for the go tool's ldflags parser
ldflags="$ldflags -X '$pkg/release.AuthenticodeSubjects=$subjects'"

echo "== build-release $v from $short, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH, $have_go"

gobuild() { # goos goarch package output
  GOOS=$1 GOARCH=$2 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$4" "$3"
}

# --- web bundle (embedded into the server, also shipped on its own) -----------------------------------
webtar="$out/librepatch-web_$v.tar.gz"
if [ "$skip_web" = 0 ]; then
  echo "== web bundle (node $have_node)"
  (cd web && npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npm run build >/dev/null)
  [ -f internal/server/webui/dist/index.html ] || die "web build produced no index.html"
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' --format=gnu \
      --exclude=dist/.keep -cf - -C internal/server/webui dist | gzip -n -9 >"$webtar"
fi

# --- binaries ----------------------------------------------------------------------------------------
echo "== Go binaries"
agent="$out/librepatch-agent_${v}_windows_amd64.exe"
gobuild windows amd64 ./cmd/librepatch-agent "$agent"
size=$(wc -c <"$agent")
[ "$size" -le "$AGENT_MAX_BYTES" ] || die "agent is $size bytes, over the $AGENT_MAX_BYTES budget"
if [ "$with_arm64" = 1 ]; then
  gobuild windows arm64 ./cmd/librepatch-agent "$out/librepatch-agent_${v}_windows_arm64.exe"
fi
gobuild linux amd64 ./cmd/librepatch-server "$out/librepatch-server_${v}_linux_amd64"
gobuild linux amd64 ./cmd/librepatch-release "$out/librepatch-release_${v}_linux_amd64"

# --- SBOMs -------------------------------------------------------------------------------------------
if [ "$skip_sbom" = 0 ]; then
  echo "== SBOMs"
  go build -trimpath -buildvcs=false -o "$work/librepatch-sbom" ./cmd/librepatch-sbom
  for f in "$out"/librepatch-agent_* "$out"/librepatch-server_* "$out"/librepatch-release_*; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    # component name: librepatch-agent_1.2.3_windows_amd64.exe -> librepatch-agent
    "$work/librepatch-sbom" go --binary "$f" --version "$v" --name "${b%%_*}" --epoch "$SOURCE_DATE_EPOCH" --out "$f.cdx.json" >/dev/null
  done
  if [ "$skip_web" = 0 ]; then
    "$work/librepatch-sbom" npm --lock web/package-lock.json --version "$v" --epoch "$SOURCE_DATE_EPOCH" --out "$out/librepatch-web_$v.cdx.json" >/dev/null
  fi
fi

# --- checksums of the reproducible set ------------------------------------------------------------------
(cd "$out" && find . -maxdepth 1 -type f ! -name 'unsigned-SHA256SUMS' ! -name 'BUILD-INFO.txt' ! -name '*.oci.tar' -printf '%f\n' \
  | sort | xargs sha256sum >unsigned-SHA256SUMS)

# --- container image (optional, needs Docker) -----------------------------------------------------------------
image_digest=""
if [ "$want_image" = 1 ]; then
  echo "== container image"
  LIBREPATCH_RELEASE_PUBKEYS="$pubkeys" "$ROOT/scripts/build-image.sh" --version "$v" --commit "$short" \
      --source-date-epoch "$SOURCE_DATE_EPOCH" --require-authenticode "$req_auth" --authenticode-subjects "$subjects" --go-version "${want_go#go}" \
      --oci-out "$out/librepatch-server_${v}_image.oci.tar" --digest-file "$out/image-digest.txt"
  image_digest=$(cat "$out/image-digest.txt")
  rm -f "$out/image-digest.txt"
fi

{
  echo "version:               $v"
  echo "commit:                $full"
  echo "source_date_epoch:     $SOURCE_DATE_EPOCH"
  echo "go:                    $have_go (pinned by go.mod toolchain)"
  [ "$skip_web" = 1 ] || echo "node:                  $have_node (pinned major $NODE_MAJOR), npm $(npm --version)"
  echo "web_lockfile_sha256:   $(sha256sum web/package-lock.json | cut -d' ' -f1)"
  echo "go_sum_sha256:         $(sha256sum go.sum | cut -d' ' -f1)"
  echo "require_authenticode:  $req_auth"
  echo "release_public_keys:   ${pubkeys:-none}"
  echo "authenticode_subjects: ${subjects:-none}"
  echo "go build flags:        -trimpath -buildvcs=false CGO_ENABLED=0 GOFLAGS=-mod=readonly"
  echo "ldflags:               $ldflags"
  [ -z "$image_digest" ] || echo "image_oci_index_digest: $image_digest"
  echo "build host:            $(uname -sm)"
} >"$out/BUILD-INFO.txt"

echo "== done: $out"
cat "$out/unsigned-SHA256SUMS"
