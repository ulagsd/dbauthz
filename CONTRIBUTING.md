# Contributing to dbauthz

## Before you change anything

- **Stack decisions** are in [docs/STACK.md](docs/STACK.md) and are frozen.
  Changing one needs an [ADR](docs/adr/README.md) with a reason.
- **Engine behaviour:** read the relevant section of
  [docs/reference.md](docs/reference.md) before changing a provider, the solver,
  the action vocabulary or the capability model. Link the page you used in the PR.

## Development setup

You need Go 1.26 or later, Docker, and golangci-lint v2.

```bash
make build      # build bin/dbauthz
make test       # unit tests
make check      # everything CI runs: licence headers, lint, tests, cross-builds
make help       # list all targets
```

Release builds use `CGO_ENABLED=0`, and the Makefile sets it for you. Do not add
a dependency that needs cgo. Only the race-detector test run enables cgo.

## Commits, branches and releases

The full rules are in [docs/WORKFLOW.md](docs/WORKFLOW.md). The essentials:

- **Branch from `main`** as `<type>/<short-description>` and open a pull
  request. PRs are squash-merged, so the PR title must follow Conventional Commits.
- **Sign off every commit** under the
  [Developer Certificate of Origin](https://developercertificate.org/):
  `git commit -s`. CI rejects pull requests with unsigned commits.
- **Use [Conventional Commits](https://www.conventionalcommits.org/)** for the
  subject line, for example `feat(postgres): read column privileges`. Release
  notes are generated from these.

## Code conventions

- Every Go file starts with `// SPDX-License-Identifier: Apache-2.0`.
  `make spdx` checks this.
- Run `make fmt` before committing. Formatting uses gofumpt and goimports.
- The provider interface exchanges only serialisable values. No open handles,
  callbacks or `any` cross it. See STACK.md section 2.2.

## Security

Never commit credentials, connection strings with passwords, or customer data,
including in tests and fixtures. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).
