#!/bin/sh
# Starts Caddy with the configuration that LIBREPATCH_BEHIND_PROXY selects (decision D110).
set -eu
case "${LIBREPATCH_BEHIND_PROXY:-false}" in
  true | TRUE | True | 1 | yes) file=Caddyfile.behind-proxy ;;
  false | FALSE | False | 0 | no | "") file=Caddyfile ;;
  *) echo "LIBREPATCH_BEHIND_PROXY must be true or false (got '$LIBREPATCH_BEHIND_PROXY')" >&2; exit 1 ;;
esac
exec caddy run --config "/etc/caddy/$file" --adapter caddyfile
