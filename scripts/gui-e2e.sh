#!/usr/bin/env bash
# Runs the browser end-to-end test against a fresh server and database.
# Requires: Go, Node, a PostgreSQL superuser URL in LIBREPATCH_TEST_PG_URL, and
# Playwright's Chromium (PLAYWRIGHT_BROWSERS_PATH).
set -euo pipefail
cd "$(dirname "$0")/.."
: "${LIBREPATCH_TEST_PG_URL:?set LIBREPATCH_TEST_PG_URL to a PostgreSQL superuser URL}"
work=$(mktemp -d)
trap 'kill ${server_pid:-0} 2>/dev/null || true; rm -rf "$work"' EXIT

(cd web && npm run build >/dev/null)
go build -o "$work/librepatch-server" ./cmd/librepatch-server
go build -o "$work/librepatch-agent" ./cmd/librepatch-agent

db="lp_gui_$(date +%s)"
psql "$LIBREPATCH_TEST_PG_URL" -qc "CREATE DATABASE $db"
dburl=$(python3 -c "import sys,urllib.parse as u;p=u.urlsplit(sys.argv[1]);print(u.urlunsplit(p._replace(path='/'+sys.argv[2])))" "$LIBREPATCH_TEST_PG_URL" "$db")

export LIBREPATCH_DEV_MODE=true LIBREPATCH_PUBLIC_URL=http://localhost:18080 LIBREPATCH_HTTP_ADDR=127.0.0.1:18080 \
  LIBREPATCH_GATEWAY_ADDR=127.0.0.1:18443 LIBREPATCH_GATEWAY_PUBLIC_ADDR=localhost:18443 LIBREPATCH_GATEWAY_SANS=127.0.0.1 \
  LIBREPATCH_CONTENT_DIR="$work/content" LIBREPATCH_DATABASE_URL="$dburl" LIBREPATCH_MASTER_KEY=$(openssl rand -hex 32) \
  LIBREPATCH_HEARTBEAT_INTERVAL=5s LIBREPATCH_WINGET_SOURCE=off
# Start like a stack that generated its own master key (decision D109): the maintenance step records the key as unsaved,
# so the first administrator has to save it before the console does anything else.
"$work/librepatch-server" migrate
psql "$dburl" -qc "INSERT INTO master_key_ack (id, key_id) VALUES (1, 'feedbeef')"
"$work/librepatch-server" serve >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do grep -q "setup token" "$work/server.log" 2>/dev/null && break; sleep 0.2; done
token=$(grep -A2 "enter this one-time setup token" "$work/server.log" | tail -1 | tr -d ' ')
if ! kill -0 "$server_pid" 2>/dev/null || [ -z "$token" ]; then
  echo "server failed to start (is port 18080/18443 in use?)"; cat "$work/server.log"; exit 1
fi

cd web
LIBREPATCH_SETUP_TOKEN="$token" LIBREPATCH_AGENT_BIN="$work/librepatch-agent" LIBREPATCH_GATEWAY=127.0.0.1:18443 \
  npx playwright test "$@" || { echo "--- server log ---"; tail -50 "$work/server.log"; exit 1; }
