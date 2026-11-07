#!/usr/bin/env bash
# Builds the same commit twice and compares SHA-256s (docs/VERIFYING_RELEASES.md, "Reproducing a build").
#
#   scripts/verify-reproducible.sh [--version 0.0.0-repro] [--commit REV] [--keep] [-- extra build-release.sh options]
#
# The two builds differ on purpose in everything that must not matter:
#   - source path       (<work>/one/librepatch-src  vs  <work>/two/some/other/place/checkout)
#   - Go build cache    (fresh and empty for each build; module downloads are shared and hash-verified by go.sum)
#   - time zone, locale, umask (022 vs 077, which changes file modes in the checkout), npm cache
#   - build time        (the second build starts at least two seconds later; nothing may embed the clock)
# Each build is a fresh `git clone` of the commit, so untracked or ignored files cannot leak in.
# It uses a throw-away release public key (any 64 hex digits work for a build), never a real one.
# Exit status: 0 identical, 1 different, 2 usage/environment problem.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$PWD

version="0.0.0-repro" commit="HEAD" keep=0
extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=${2:?}; shift 2 ;;
    --commit) commit=${2:?}; shift 2 ;;
    --keep) keep=1; shift ;;
    --) shift; extra=("$@"); break ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

rev=$(git rev-parse --verify "${commit}^{commit}")
work=$(mktemp -d)
cleanup() {
  if [ "$keep" = 0 ]; then chmod -R u+w "$work" 2>/dev/null || true; rm -rf "$work"; else echo "kept $work"; fi
}
trap cleanup EXIT

key=0000000000000000000000000000000000000000000000000000000000000001
echo "verify-reproducible: commit ${rev:0:12}, version $version, work dir $work"
gomod=${GOMODCACHE:-$(go env GOMODCACHE)}

build() { # name checkout-dir tz locale umask
  local name=$1 dir=$2 tz=$3 loc=$4 um=$5
  mkdir -p "$(dirname "$dir")"
  (
    umask "$um"
    git clone -q --no-hardlinks "$repo" "$dir"
    git -C "$dir" checkout -q --detach "$rev"
    export TZ="$tz" LC_ALL="$loc" GOCACHE="$work/gocache-$name" GOMODCACHE="$gomod" npm_config_cache="$work/npmcache-$name"
    cd "$dir"
    scripts/build-release.sh --version "$version" --release-pubkeys "$key" --authenticode-subjects "LibrePatch Repro Test" --out "$work/out-$name" ${extra[@]+"${extra[@]}"} >"$work/log-$name.txt" 2>&1
  ) || { tail -30 "$work/log-$name.txt" >&2; echo "build $name failed" >&2; exit 2; }
}

build one "$work/one/librepatch-src" UTC C.UTF-8 022
sleep 2
build two "$work/two/some/other/place/checkout" Pacific/Auckland C 077

echo
echo "build one:"; sed 's/^/  /' "$work/out-one/unsigned-SHA256SUMS"
sums1=$work/out-one/unsigned-SHA256SUMS
sums2=$work/out-two/unsigned-SHA256SUMS
if diff -u "$sums1" "$sums2" >"$work/diff.txt"; then
  echo
  echo "REPRODUCIBLE: both builds produced identical SHA-256 sums for $(wc -l <"$sums1") files."
  exit 0
fi
echo
echo "NOT REPRODUCIBLE. Differences:"
cat "$work/diff.txt"
for f in $(awk 'NR==FNR{a[$2]=$1;next} ($2 in a) && a[$2]!=$1 {print $2}' "$sums1" "$sums2"); do
  echo "--- $f"
  if command -v diffoscope >/dev/null; then
    diffoscope --text - "$work/out-one/$f" "$work/out-two/$f" | head -60 || true
  else
    echo "$(cmp -l "$work/out-one/$f" "$work/out-two/$f" 2>/dev/null | wc -l) differing bytes (install diffoscope for details)"
  fi
done
keep=1
exit 1
