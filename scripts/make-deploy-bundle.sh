#!/usr/bin/env bash
# Builds the install files for a release (docs/RUNBOOK.md, 2.2):
#   librepatch-deploy-<version>.zip   the compose file, .env.example and a README
#   $LIBREPATCH_COMPOSE_OUT           (optional) the same compose file alone, for pasting into a graphical container manager
#
#   scripts/make-deploy-bundle.sh 1.2.3 [out.zip]
#
# The compose file has the version baked in as its default image tag, and the agents' update public key (when
# LIBREPATCH_RELEASE_PUBKEYS is set) as the default of its settings block, so it always starts the images it was made
# for. Everything is in the images (decision D110); nothing is needed next to the compose file.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?usage: make-deploy-bundle.sh VERSION [OUT.zip]}
out=${2:-librepatch-deploy-$version.zip}
case $out in /*) ;; *) out="$PWD/$out" ;; esac
[[ $version =~ ^[0-9A-Za-z.+-]+$ ]] || { echo "make-deploy-bundle: bad version '$version'" >&2; exit 1; }
command -v zip >/dev/null || { echo "make-deploy-bundle: zip is required" >&2; exit 1; }

# The image compose file must be current (make generate keeps it so); refuse a stale one.
tmpc=$(mktemp)
scripts/gen-image-compose.sh "$tmpc"
cmp -s "$tmpc" deploy/docker-compose.image.yml || { rm -f "$tmpc"; echo "make-deploy-bundle: deploy/docker-compose.image.yml is out of date (run make generate)" >&2; exit 1; }
rm -f "$tmpc"

root="librepatch-deploy-$version"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$root/deploy"

# The default tag becomes this version; LIBREPATCH_VERSION in deploy/.env still overrides it.
compose="$stage/$root/deploy/docker-compose.image.yml"
sed "s/\${LIBREPATCH_VERSION:-latest}/\${LIBREPATCH_VERSION:-$version}/" deploy/docker-compose.image.yml > "$compose"
grep -q "LIBREPATCH_VERSION:-$version" "$compose" || { echo "make-deploy-bundle: could not set the default version" >&2; exit 1; }
cp deploy/.env.example "$stage/$root/deploy/"
# With an update signing key configured, the server must trust its PUBLIC half to accept the signed update file.
pubkeys=${LIBREPATCH_RELEASE_PUBKEYS:-}
if [ -n "$pubkeys" ]; then
  [[ $pubkeys =~ ^[0-9a-f]{64}(,[0-9a-f]{64})*$ ]] || { echo "make-deploy-bundle: LIBREPATCH_RELEASE_PUBKEYS must be comma-separated 64-character lowercase hex keys" >&2; exit 1; }
  grep -q '^#LIBREPATCH_RELEASE_PUBLIC_KEYS=$' "$stage/$root/deploy/.env.example" || { echo "make-deploy-bundle: .env.example has no LIBREPATCH_RELEASE_PUBLIC_KEYS line" >&2; exit 1; }
  sed -i "s/^#LIBREPATCH_RELEASE_PUBLIC_KEYS=\$/LIBREPATCH_RELEASE_PUBLIC_KEYS=$pubkeys/" "$stage/$root/deploy/.env.example"
  grep -q 'release_public_keys: &release_public_keys \${LIBREPATCH_RELEASE_PUBLIC_KEYS:-}$' "$compose" || { echo "make-deploy-bundle: the compose file has no release_public_keys setting" >&2; exit 1; }
  sed -i "s/^\(  release_public_keys: &release_public_keys \${LIBREPATCH_RELEASE_PUBLIC_KEYS:-\)}\$/\1$pubkeys}/" "$compose"
  grep -q "LIBREPATCH_RELEASE_PUBLIC_KEYS:-$pubkeys}" "$compose" || { echo "make-deploy-bundle: could not set the update public key" >&2; exit 1; }
fi
if [ -n "${LIBREPATCH_COMPOSE_OUT:-}" ]; then cp "$compose" "$LIBREPATCH_COMPOSE_OUT"; fi

cat > "$stage/$root/README.txt" <<README
LibrePatch server $version: install files

The whole stack is ONE compose file, deploy/docker-compose.image.yml. Everything else (the web proxy settings, the
database setup) is inside the images, which Docker downloads from ghcr.io/auzring1 when you start the stack.

1. Set your host name: open deploy/docker-compose.image.yml, find the block "YOUR SETTINGS" at the top and replace
   change-me.example.com with the DNS name of this server. (Behind your own reverse proxy, set the other lines in that
   block as described in docs/RUNBOOK.md, 2.1. Instead of editing the file you can copy deploy/.env.example to
   deploy/.env and set the same names there: a value in .env wins.)
2. Start it (add sudo if your user is not in the docker group):
       docker compose -f deploy/docker-compose.image.yml up -d
   (with a deploy/.env file: add  --env-file deploy/.env)
   The database passwords and the master key are created for you on this first start.
3. First-run setup token:
       docker compose -f deploy/docker-compose.image.yml logs server | grep -A2 "setup token"
4. After you sign in for the first time the console shows the MASTER KEY. Save it somewhere other than this server
   (a password manager): without it a restored database cannot be read again.

Agent updates: the public key your agents trust for automatic updates is already in the settings block (when this
release was made with an update key). The signed update file (.lprel) from the same release goes under
"Settings → Agent updates" in the console.

Update later: download the newer librepatch-deploy zip (or the newer compose file) and copy your host name into it, or
change the version in deploy/.env (LIBREPATCH_VERSION=<new version>), then run the same command with "pull" and again
with "up -d". Back up first.

Full instructions: docs/RUNBOOK.md in the repository, section 2.2 (https://github.com/auzring1/LibrePatch).
README

rm -f "$out"
(cd "$stage" && zip -qr -X "$out" "$root")
echo "wrote $out"
