# Contributing to LibrePatch

Thank you for helping. Bug reports, ideas, documentation fixes and pull requests are all welcome.

## Before you start

- **Questions and ideas:** open an issue and describe what you are trying to do. For anything larger than a small fix,
  please talk it through first, so nobody spends a weekend on something that will not fit.
- **Security problems:** do not use a public issue. See [SECURITY.md](SECURITY.md).
- **Be kind.** Assume good intent, be patient with newcomers, and keep criticism about the code, not the person.
  Harassment and personal attacks are not tolerated; the maintainer may remove comments and block accounts.

## Reporting a bug

Say what you did, what you expected and what happened, plus the version (Settings > About) and, for agent problems, the
relevant part of `agent.log`. Remove host names, addresses and anything private first. Never post secrets.

## Making a change

1. Fork the repository and create a branch.
2. Read [CLAUDE.md](CLAUDE.md) for the layout, the commands and the conventions. The same notes apply to people.
3. Make the change **with a test**. Every behavior change needs one, and so does every bug fix (a test that fails without it).
4. Run the checks before you push:
   ```bash
   make dev-db                       # a throwaway PostgreSQL; export the URL it prints as LIBREPATCH_TEST_PG_URL
   go vet ./... && go test ./...
   cd web && npx tsc --noEmit && npx vitest run
   scripts/gui-e2e.sh                # the browser test, if you touched the console or the API
   ```
   If you changed the database, the API or the protocol, run `make generate` and commit the generated files.
5. Keep the pull request focused: one change, explained in plain words (what and why). Update the docs it touches.
   Design choices that someone will later wonder about belong in [docs/DECISIONS.md](docs/DECISIONS.md).

## Rules that matter here

- **Security first.** A change that weakens authentication, signing, auditing or access control needs a very good reason,
  written down. Every state-changing API action is audited and has its own permission.
- **Say what you verified.** Windows-only code cannot be tested on Linux; if you could not run something on a real machine,
  say so in the pull request instead of implying it works.
- **Dependencies** must be permissive licenses (MIT, BSD, Apache-2.0, ISC, MPL-2.0 at file level). `make licenses` checks this.
- **No real names.** Use made-up organizations and hosts (for example "Contoso Health", `example.org`) in tests, docs and
  screenshots.

## License of contributions

By submitting a contribution you agree that it is licensed under the same terms as the project, the
[GNU AGPL-3.0 or later](LICENSE). You keep the copyright in your contribution.
