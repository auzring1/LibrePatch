# LibrePatch: build, test and conventions

Self-hosted Windows endpoint patch and software management: a Go agent, a Go server (REST API, SSE, embedded React console)
and PostgreSQL, run with docker compose. Open source under the GNU AGPL-3.0. Start with `README.md`, `docs/ARCHITECTURE.md`,
`docs/DECISIONS.md` and `docs/RUNBOOK.md`. The README, `CONTRIBUTING.md`, `SECURITY.md` and `TRADEMARKS.md` are written for the
public: keep real names, hosts and addresses out of the repository.

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
- Database changes are goose migrations in `db/migrations` plus sqlc queries in `db/queries`.
- Every state-changing API action writes an audit entry (`audit.Write`/`audit.Log`) and has an RBAC permission
  (`internal/server/auth/rbac.go`). Update `api/openapi.yaml` with the API.
- A guard test forbids the owner's real organization name in code and tests; use "Contoso Health" in fixtures.
- Record design choices in `docs/DECISIONS.md` and security-relevant ones in `docs/THREAT-MODEL.md`.
- Say plainly what was and was not verified. Windows-only agent paths, the real winget CDN and a real production host are
  not testable from a Linux sandbox.
- Never copy production secrets into a development checkout, and never regenerate a production master key (it makes the
  database unreadable).
