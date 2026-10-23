# LibrePatch: notes for Claude Code sessions

Open source under the GNU AGPL-3.0 (D100). There is no licensing system, no device cap and no telemetry. The README, `CONTRIBUTING.md`,
`SECURITY.md` and `TRADEMARKS.md` are written for the public: keep real names, hosts and addresses out of the repository.

Self-hosted Windows endpoint patch and software management: a Go agent, a Go server (REST API, SSE, embedded
React console) and PostgreSQL, run with docker compose. Security first: mTLS, signed jobs, mandatory MFA, RBAC, hash-chained
audit. Start with `README.md`, `docs/ARCHITECTURE.md`, `docs/DECISIONS.md` (latest decision: D145) and `docs/RUNBOOK.md`.

## The maintainer and the deployment
- The maintainer is an IT administrator, not a full-time developer. Explain things in plain words and ask when a request is unclear.
- A typical production setup is a Synology NAS running Docker (Container Manager) behind DSM's reverse proxy, for a few hundred
  PCs. The console goes through the proxy to Caddy over plain HTTP (`deploy/caddy/Caddyfile.behind-proxy`); agents connect directly to
  the gateway port. Host names and addresses of real installations are kept out of the repository on purpose.
- This checkout is a development copy. Its `deploy/.env` and its Docker volumes (`secrets_*`, which hold the generated passwords and master key) are its own. Never copy production secrets
  here, and never regenerate a production master key (it makes the database unreadable).
- Changes reach production by rebuilding the server image. A server-only change needs no new agent release; an agent
  change does (upload a new signed `.lprel` under Agent releases).

## Commands
- Tests need PostgreSQL: `make dev-db` (port 55432), then
  `LIBREPATCH_TEST_PG_URL=postgres://postgres:...@127.0.0.1:55432/postgres?sslmode=disable go test ./...`
  (`LIBREPATCH_REQUIRE_DB=1` makes missing-DB a failure instead of a skip).
- Console: `cd web && npx tsc --noEmit && npx vitest run`. Browser end-to-end: `scripts/gui-e2e.sh` (about 3 minutes).
- Generated code: `make generate` (protobuf, sqlc, `npm run gen:api` TypeScript types). Commit the generated files.
- Windows agent: `GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o librepatch-agent.exe ./cmd/librepatch-agent`.
- On Windows use Git Bash for the `.sh` scripts (`& "C:\Program Files\Git\bin\bash.exe" scripts/gui-e2e.sh`);
  plain `bash` may resolve to WSL.

## Conventions
- Database changes are goose migrations in `db/migrations` (latest 00031) plus sqlc queries in `db/queries`.
- Every state-changing API action writes an audit entry (`audit.Write`/`audit.Log`) and has an RBAC permission
  (`internal/server/auth/rbac.go`). Update `api/openapi.yaml` with the API.
- A guard test forbids the owner's real organization name in code and tests; use "Contoso Health" in fixtures.
- Record design choices in `docs/DECISIONS.md` (next number D146) and security-relevant ones in `docs/SECURITY.md`.
- Say plainly what was and was not verified. Windows-only agent paths, the real winget CDN and the Synology itself are
  not testable from a Linux sandbox.
- Commit messages end with the `Co-Authored-By` and `Claude-Session` trailers the session gives you.

## Where things stand
- Done: phases 1 to 6, branding and design system, navigation, settings framework, DSM reverse-proxy mode, Software
  updates page, winget community index (updates need no catalog entry), admin "Mark as verified" (D99), and the fix that
  stops a non-GUID product code reaching the agent (Folge update).
- Open or unproven: restart-delay after a reboot on real PCs (suspected clock skew; ask for `agent.log`), faster
  reconnect after reboot needs a new agent release, behaviour against the real winget CDN, and anything that runs only
  on real Windows (see `docs/SECURITY.md`).
