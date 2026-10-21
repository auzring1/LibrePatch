# LibrePatch developer tasks. Tools: Go (see go.mod toolchain), Node 22, Docker.
# Run `make help` for targets.
SHELL := /bin/bash
VERSION ?= 0.1.0-dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/auzring1/librepatch/internal/shared/version.Version=$(VERSION) -X github.com/auzring1/librepatch/internal/shared/version.Commit=$(COMMIT)
AGENT_MAX_BYTES := 17825792   # 17 MiB budget (ARCHITECTURE §3.1, D129)
TEST_PG ?= postgres://postgres:devpostgres@127.0.0.1:55432/postgres?sslmode=disable

.PHONY: help
help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n",$$1,$$2}'

.PHONY: tools
tools: ## Install pinned code generators and linters into GOBIN
	go install github.com/bufbuild/buf/cmd/buf@v1.73.0
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
	CGO_ENABLED=1 go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
	go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
	go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0
	go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
	go install github.com/google/go-licenses/v2@v2.0.1

.PHONY: generate
generate: ## Regenerate protobuf, sqlc and TypeScript API code
	go generate ./internal/shared/brand
	buf generate
	sqlc generate
	cd web && npm run gen:api
	scripts/gen-image-compose.sh

.PHONY: check-generated
check-generated: generate ## Fail if generated code is out of date
	git diff --exit-code -- gen web/src/api/schema.d.ts web/src/brand.generated.ts deploy/docker-compose.image.yml

.PHONY: web
web: ## Build the web console into the server's embed directory
	cd web && npm ci --no-audit --no-fund && npm run build

.PHONY: build
build: web ## Build server (linux) and agent (windows + linux test build) into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/librepatch-server ./cmd/librepatch-server
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/librepatch-agent.exe ./cmd/librepatch-agent
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/librepatch-agent-linux ./cmd/librepatch-agent

.PHONY: agent
agent: ## Build only the Windows agent and enforce the size budget
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/librepatch-agent.exe ./cmd/librepatch-agent
	@size=$$(stat -c %s bin/librepatch-agent.exe); echo "agent size: $$size bytes (budget $(AGENT_MAX_BYTES))"; \
	  test $$size -le $(AGENT_MAX_BYTES) || { echo "agent binary over budget"; exit 1; }

.PHONY: winres
winres: ## Regenerate the agent's Windows version resource (needs: go install github.com/tc-hib/go-winres@v0.3.3)
	go run ./internal/shared/brand/gen -winres cmd/librepatch-agent/winres/winres.json
	cd cmd/librepatch-agent && go-winres make --in winres/winres.json --out rsrc --arch amd64

.PHONY: dev-db
dev-db: ## Start a throwaway PostgreSQL for tests on 127.0.0.1:55432
	docker run -d --rm --name librepatch-dev-pg -e POSTGRES_PASSWORD=devpostgres -p 127.0.0.1:55432:5432 postgres:16-alpine
	@until docker exec librepatch-dev-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done; echo "export LIBREPATCH_TEST_PG_URL='$(TEST_PG)'"

.PHONY: test
test: ## Unit + DB + in-process end-to-end tests (needs LIBREPATCH_TEST_PG_URL, see dev-db)
	go test -race -count=1 ./...
	cd web && npm test

.PHONY: test-gui
test-gui: ## Browser end-to-end test (Playwright + real server + real agent)
	./scripts/gui-e2e.sh

.PHONY: image
image: ## Build the server container image
	docker build -f deploy/Dockerfile.server --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t librepatch/server:dev .

.PHONY: images-extra
images-extra: ## Build the web proxy (Caddy) and database container images
	docker build -t librepatch/caddy:dev deploy/caddy
	docker build -t librepatch/postgres:dev deploy/postgres

.PHONY: test-compose
test-compose: image images-extra ## Full docker-compose stack + real agent integration test
	go test -tags compose -count=1 -timeout 15m ./test/integration/

.PHONY: lint
lint: ## go vet, staticcheck, gosec (linux + windows), semgrep, typecheck
	go vet ./...
	GOOS=windows go vet ./...
	staticcheck ./...
	GOOS=windows staticcheck ./internal/agent/... ./cmd/librepatch-agent/...
	gosec -quiet -exclude-generated -exclude-dir=test ./...
	# G103 (unsafe) is inherent to Win32 FFI in the agent; those call sites are reviewed.
	GOOS=windows gosec -quiet -exclude-generated -exclude=G103 ./internal/agent/... ./cmd/librepatch-agent/...
	docker run --rm -v "$$PWD:/src" -w /src semgrep/semgrep:latest semgrep scan --config .semgrep.yml --error --metrics=off --quiet
	cd web && npx tsc --noEmit -p .

.PHONY: fuzz
fuzz: ## Short fuzzing run (20s per target) over every parser that sees untrusted input
	@set -e; for t in \
	  ./internal/shared/installer:FuzzCommandLine ./internal/shared/installer:FuzzValidateArg ./internal/shared/installer:FuzzExtractZip \
	  ./internal/server/catalog:FuzzParseManifest ./internal/shared/vercmp:FuzzKey ./internal/server/inventory:FuzzNormalize \
	  ./internal/server/groups:FuzzCompile ./internal/agent/hardware:FuzzParseSMBIOS \
	  ./internal/shared/envelope:FuzzOpenSigned ./internal/shared/envelope:FuzzOpenRaw ./internal/shared/bundle:FuzzParse ./internal/shared/release:FuzzBundle ./internal/shared/release:FuzzVerify \
	  ./internal/agent/jobs:FuzzValidateBodies ./internal/agent/inventory:FuzzScanUninstall ./internal/server/backup:FuzzWalker ./internal/server/backup:FuzzManifest; do \
	  go test $${t%%:*} -run XXX -fuzz $${t##*:} -fuzztime 20s; done

.PHONY: vuln
vuln: ## govulncheck + npm audit
	govulncheck ./...
	GOOS=windows govulncheck ./cmd/librepatch-agent/...
	cd web && npm audit --omit=dev --audit-level=high

.PHONY: licenses
licenses: ## Enforce the permissive-license allow-list
	./scripts/check-licenses.sh

.PHONY: up
up: ## Start the production-style stack (deploy/.env must exist)
	docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build

.PHONY: release-dryrun
release-dryrun: ## Rehearse the release pipeline locally with throw-away keys (dist-release/dryrun/)
	./scripts/release-dryrun.sh --clean

.PHONY: verify-reproducible
verify-reproducible: ## Build the same commit twice in different directories and compare SHA-256s (~3 min)
	./scripts/verify-reproducible.sh

.PHONY: check-actions
check-actions: ## Fail if a GitHub Action is not pinned to a full commit SHA
	./scripts/check-actions-pinned.sh
