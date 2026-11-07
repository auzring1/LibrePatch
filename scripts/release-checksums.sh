#!/usr/bin/env bash
# Writes SHA256SUMS for the final release directory (after Authenticode signing, so the signed agent and the
# MSI are listed with their final digests). The file lists every regular file in DIR except itself and the
# cosign bundles that sign it; cosign then signs SHA256SUMS (release.yml) and everything is covered transitively.
#
#   scripts/release-checksums.sh DIR
set -euo pipefail
dir=${1:?usage: release-checksums.sh DIR}
cd "$dir"
rm -f SHA256SUMS
find . -maxdepth 1 -type f ! -name 'SHA256SUMS' ! -name 'SHA256SUMS.*' -printf '%f\n' \
  | LC_ALL=C sort | xargs sha256sum >SHA256SUMS
echo "wrote $dir/SHA256SUMS ($(wc -l <SHA256SUMS) files)"
