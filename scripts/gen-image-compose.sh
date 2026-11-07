#!/usr/bin/env bash
# Writes deploy/docker-compose.image.yml from deploy/docker-compose.yml.
#
# The two files are the same stack. The only difference: the image file PULLS the three published images
# (ghcr.io/<owner>/librepatch-server, -caddy and -postgres) instead of building them from source, so updating is
# "pull and restart", and an install needs nothing but this one file (decision D110).
# Do not edit the image file by hand; `make generate` rewrites it and `make check-generated` (CI) fails on drift.
set -euo pipefail
cd "$(dirname "$0")/.."

src=deploy/docker-compose.yml
out=${1:-deploy/docker-compose.image.yml}

awk '
  NR == 1 { print "# The whole LibrePatch stack in ONE file: the three images are PULLED from the registry, nothing else is needed."
            print "# TO INSTALL: edit ONLY the \"YOUR SETTINGS\" block below (at least the host name), then start it:"
            print "#   docker compose up -d          (or paste this file into a new stack in a graphical container manager)"
            print "# More: docs/RUNBOOK.md, \"Install from the published images\"."
            print "# (For maintainers: this file is generated from deploy/docker-compose.yml by scripts/gen-image-compose.sh; change the source.)"
            skip_header = 1 }
  skip_header && /^#/ { next }
  { skip_header = 0 }
  /^# The server image is built once/ { next }
  /^x-[a-z]+-build:/ { in_anchor = 1; next }
  in_anchor && /^  / { next }
  { in_anchor = 0 }
  /^    build: \*[a-z]+-build$/ { next }
  /^    image: librepatch\/[a-z]+:/ {
    match($0, /librepatch\/[a-z]+:/)
    name = substr($0, RSTART + 11, RLENGTH - 12)
    print "    image: ${LIBREPATCH_REGISTRY:-ghcr.io/auzring1}/librepatch-" name ":${LIBREPATCH_VERSION:-latest}"
    print "    pull_policy: always"
    next
  }
  { print }' "$src" > "$out"
