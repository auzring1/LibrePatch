## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## How it was checked

<!-- Tests you added or ran. Say plainly what you could NOT check (for example anything that only runs on real Windows). -->

- [ ] `go vet ./... && go test ./...`
- [ ] `cd web && npx tsc --noEmit && npx vitest run` (if the console changed)
- [ ] `scripts/gui-e2e.sh` (if the console or the API changed)
- [ ] Generated code is up to date (`make generate`) and docs are updated
- [ ] No real organization names, addresses, tokens or other private data
