# dbauthz — instructions for Claude Code

Policy-driven access control for databases. Go, pure Go builds (`CGO_ENABLED=0`).

## Read first

- [docs/STACK.md](docs/STACK.md): frozen technology decisions. Changing one needs an ADR in [docs/adr/](docs/adr/).
- [docs/WORKFLOW.md](docs/WORKFLOW.md): commits, branching, versioning and releases. Follow it for every commit, branch, tag and release.
- [docs/reference.md](docs/reference.md): read the engine's section before changing a provider, the solver, the action vocabulary or the capability model.

## Rules

- Commit only when asked. Never push, tag or release without an explicit request.
- Before committing, create a branch named `<type>/<short-description>` unless the maintainer says to commit to `main`.
- Commit messages follow Conventional Commits and are signed off with `git commit -s`.
- Commits are authored by the maintainer alone: no `Co-Authored-By` trailer for Claude and no "Generated with Claude Code" text in commits or PRs.
- Run `make check` before reporting work as done. Report failures with their output.
- Every Go file starts with `// SPDX-License-Identifier: Apache-2.0`.
- Never add a dependency that needs cgo.
- Never put credentials, real connection strings or customer data in code, tests, fixtures or docs.

## Commands

```bash
make build   # bin/dbauthz
make test    # unit tests
make check   # licence headers, lint, tests, cross-builds: what CI runs
make fmt     # gofumpt + goimports
```
