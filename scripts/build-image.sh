#!/usr/bin/env bash
# Builds the server container image from deploy/Dockerfile.server the way a release does.
#
#   LIBREPATCH_RELEASE_PUBKEYS=<hex>[,<hex>] scripts/build-image.sh --version 1.2.3 --commit <short> \
#       --source-date-epoch <n> [--require-authenticode true] [--go-version 1.27.3] \
#       (--oci-out FILE | --push REGISTRY/NAME:TAG) [--digest-file FILE]
#
#   --oci-out   write an OCI archive (nothing is pushed; used by the dry run and by reproducibility checks)
#   --push      build and push; the pushed manifest digest is written to --digest-file (sign THAT digest, never a tag)
#
# Reproducibility: base images are pinned by digest in the Dockerfile; BuildKit's attestations are turned off
# (cosign and GitHub attestations are attached afterwards, see .github/workflows/release.yml); layer and
# config timestamps are rewritten to --source-date-epoch (BuildKit >= 0.13, `rewrite-timestamp=true`).
# The server binary inside is built with the same flags as scripts/build-release.sh, so it should be
# byte-identical to librepatch-server_<v>_linux_amd64 from that script; `--go-version` makes the build fail if the
# pinned base image carries a different Go release.
#
# Needs Docker with buildx and a daemon. NOT exercised in the authoring sandbox (no Docker daemon there).
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "build-image: $*" >&2; exit 1; }

version="" commit="unknown" sde="" req_auth="" subjects="" go_version="" oci="" push="" digest_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=${2:?}; shift 2 ;;
    --commit) commit=${2:?}; shift 2 ;;
    --source-date-epoch) sde=${2:?}; shift 2 ;;
    --require-authenticode) req_auth=${2:?}; shift 2 ;;
    --authenticode-subjects) subjects=${2:?}; shift 2 ;;
    --go-version) go_version=${2:?}; shift 2 ;;
    --oci-out) oci=${2:?}; shift 2 ;;
    --push) push=${2:?}; shift 2 ;;
    --digest-file) digest_file=${2:?}; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$version" ] && [ -n "$sde" ] || die "--version and --source-date-epoch are required"
[ -n "$oci" ] || [ -n "$push" ] || die "one of --oci-out or --push is required"
[ -z "$oci" ] || [ -z "$push" ] || die "--oci-out and --push are exclusive"
[[ $sde =~ ^[0-9]+$ ]] || die "--source-date-epoch must be a number"

command -v docker >/dev/null || die "docker is required"
builder=librepatch-release
if ! docker buildx inspect "$builder" >/dev/null 2>&1; then
  opts=()
  # Pin BuildKit itself by digest in the release environment: LIBREPATCH_BUILDKIT_IMAGE=moby/buildkit:vX.Y.Z@sha256:...
  if [ -n "${LIBREPATCH_BUILDKIT_IMAGE:-}" ]; then opts+=(--driver-opt "image=$LIBREPATCH_BUILDKIT_IMAGE"); fi
  docker buildx create --name "$builder" --driver docker-container ${opts[@]+"${opts[@]}"} >/dev/null
fi

args=(buildx build --builder "$builder" -f deploy/Dockerfile.server
  --build-arg "VERSION=$version" --build-arg "COMMIT=$commit"
  --build-arg "RELEASE_PUBLIC_KEYS=${LIBREPATCH_RELEASE_PUBKEYS:-}" --build-arg "REQUIRE_AUTHENTICODE=$req_auth" --build-arg "AUTHENTICODE_SUBJECTS=$subjects"
  --build-arg "SOURCE_DATE_EPOCH=$sde"
  --provenance=false --sbom=false)
[ -z "$go_version" ] || args+=(--build-arg "EXPECT_GO_VERSION=$go_version")

meta=$(mktemp)
trap 'rm -f "$meta"' EXIT
if [ -n "$oci" ]; then
  args+=(--output "type=oci,dest=$oci,rewrite-timestamp=true")
else
  args+=(--output "type=image,name=$push,push=true,rewrite-timestamp=true" --metadata-file "$meta")
fi
SOURCE_DATE_EPOCH=$sde docker "${args[@]}" .

if [ -n "$oci" ]; then
  digest=$(tar -xOf "$oci" index.json | jq -r '.manifests[0].digest')
else
  digest=$(jq -r '."containerimage.digest"' "$meta")
fi
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "could not determine the image digest (got '$digest')"
echo "image digest: $digest"
if [ -n "$digest_file" ]; then echo "$digest" >"$digest_file"; fi
