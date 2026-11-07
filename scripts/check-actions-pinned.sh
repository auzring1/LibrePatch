#!/usr/bin/env bash
# Fails if a GitHub Actions workflow uses a third-party action that is not pinned to a full commit SHA
# with the human-readable version in a trailing comment (docs/THREAT-MODEL.md supply chain; convention used by
# every workflow here):
#
#   - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
#
# Allowed without a SHA: local actions/workflows (./...) and docker://image@sha256:<digest>.
# Tags and branches (@v4, @main) are rejected because they can be moved after review.
#
#   scripts/check-actions-pinned.sh [file ...]     (default: .github/workflows/*.yml and .github/actions/**/action.yml)
set -euo pipefail
cd "$(dirname "$0")/.."

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
  while IFS= read -r f; do files+=("$f"); done < <(find .github -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)
fi

bad=0
for f in "${files[@]}"; do
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    # a `uses:` key (optionally after "- "), ignoring commented-out lines
    [[ $line =~ ^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*(.*)$ ]] || continue
    rest=${BASH_REMATCH[2]}
    ref=${rest%%#*}
    comment=""
    [[ $rest == *"#"* ]] && comment=${rest#*#}
    ref=$(echo "$ref" | tr -d "\"'" | tr -d '[:space:]')
    case "$ref" in
      ./*|../*) continue ;;
      docker://*@sha256:????????????????????????????????????????????????????????????????) continue ;;
    esac
    if [[ ! $ref =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$ ]]; then
      echo "$f:$n: not pinned to a full commit SHA: $ref" >&2
      bad=1
    elif [[ ! $comment =~ [vV]?[0-9]+(\.[0-9]+)* ]]; then
      echo "$f:$n: pinned, but the version is missing in the trailing comment: $ref" >&2
      bad=1
    fi
  done <"$f"
done
if [ "$bad" != 0 ]; then
  echo "Pin each action to the commit of a reviewed release (git ls-remote --tags https://github.com/OWNER/REPO) and put the tag in a comment." >&2
  exit 1
fi
echo "all actions are pinned to full commit SHAs (${#files[@]} files checked)"
