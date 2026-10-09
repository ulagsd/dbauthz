# dbauthz — Engineering Workflow

> How changes move from a branch to a signed release. Contributors and coding
> agents follow this document. Changing a rule here needs an
> [ADR](adr/README.md), the same as a stack decision.
>
> Items marked **TO DECIDE** belong to the HLD and are settled there.

---

## 1. Commits

### 1.1 Rules

- **One logical change per commit.** A refactor and a feature are two commits.
- **Sign off every commit** under the DCO: `git commit -s`. CI rejects PRs with
  unsigned commits.
- **The human contributor is the author.** No AI co-author trailers, no
  "Generated with" lines.
- **Never commit secrets,** connection strings with passwords, real hostnames of
  private systems, or customer data. This includes tests, fixtures and examples.
- **Every commit on `main` builds and passes `make check`.**

### 1.2 Message format — Conventional Commits

```
<type>(<scope>): <summary in the imperative, lower case, no full stop>

<body: what changed and why, wrapped at 72 columns>

<footers>
Signed-off-by: Your Name <you@example.com>
```

The subject line stays under 72 characters. The body explains why the change
was made. The diff already shows what changed.

| Type | Use for | Version bump after 1.0 |
|---|---|---|
| `feat` | New user-visible capability | minor |
| `fix` | Bug fix | patch |
| `perf` | Performance improvement, no behaviour change | patch |
| `refactor` | Code change with no behaviour change | none |
| `test` | Tests only | none |
| `docs` | Documentation only | none |
| `build` | Build system, Makefile, goreleaser, dependencies | none |
| `ci` | GitHub Actions workflows | none |
| `chore` | Anything else that ships nothing | none |
| `revert` | Reverts a previous commit | depends |

**Scopes** follow the components: `cli`, `api`, `authz`, `policy`, `solver`,
`planner`, `executor`, `store`, `audit`, `secrets`, `worker`, `agent`,
`operator`, `helm`, and one per engine, such as `postgres` or `mysql`. Leave
the scope out when a change spans many components.

**Breaking changes** add `!` after the scope and a `BREAKING CHANGE:` footer
that tells users what to do:

```
feat(policy)!: rename "effect" to "decision" in policy documents

BREAKING CHANGE: policy documents must use "decision" instead of "effect".
Run `dbauthz policy migrate` to rewrite existing files.
```

### 1.3 What counts as breaking

Any change that makes a user edit something or change a script:

- **Policy document format:** field names, the resource-path grammar, action names, or what a policy means
- **API:** anything `buf breaking` flags
- **CLI:** command names, flags, exit codes, or JSON output fields
- **Configuration:** keys in `config.yaml` or `DBAUTHZ_*` environment variables
- **Control-plane store:** a migration that cannot be rolled back
- **Generated SQL:** a change to which grants a given policy produces. The
  golden files make this visible in review

---

## 2. Branching — trunk-based

- **`main` is the only long-lived branch.** It is always releasable.
- **Work happens on short-lived branches** cut from `main`, and each branch
  merges back through a pull request. Aim for branches that live less than three days.
- **Branch names:** `<type>/<short-description>`, for example
  `feat/postgres-introspection` or `fix/solver-column-deny`.
- **Merge by squash.** The PR title becomes the single commit on `main`, so it
  must follow the Conventional Commits format. CI checks this.
- **Unfinished features** merge behind a hidden CLI flag or an unregistered
  provider, not as a long-running branch.
- **Release branches** do not exist before v1.0.0. After v1.0.0, each minor
  version gets a `release/vX.Y` branch for patch fixes. See section 4.4.

### 2.1 Branch protection for `main`

Configure this in the GitHub repository settings:

- **Require a pull request** before merging
- **Require status checks to pass:** the CI jobs and the DCO check
- **Require linear history,** and allow only squash merging
- **Block force pushes** and branch deletion
- **Protect `v*` tags** so only maintainers can create them

### 2.2 Pull requests

- Fill in the PR template.
- Link the [reference.md](reference.md) page you relied on for any change to
  engine behaviour.
- Add or update golden files whenever generated SQL changes.
- A PR that changes a STACK.md decision includes its ADR.

---

## 3. Versioning — Semantic Versioning

Versions use the form `vMAJOR.MINOR.PATCH`, as defined by [SemVer 2.0.0](https://semver.org/).

| Stage | Meaning |
|---|---|
| `v0.x.y` | Before 1.0. A minor bump may break things, and the release notes say how |
| `v0.x.y-alpha.N` | Feature-incomplete. For early testers |
| `v0.x.y-beta.N` | Feature-complete for that minor version. For wider testing |
| `v0.x.y-rc.N` | Release candidate. Only fixes after this |
| `v1.0.0` and later | Breaking changes only in a major version |

These all carry the same version:

- **The binary,** from `dbauthz version`
- **The container image tag**
- **The Helm chart's `appVersion`**
- **The git tag**

The Helm chart's own `version` moves separately whenever the chart changes.

**Compatibility promises from v1.0.0:**
- **Deprecations.** A deprecated flag, config key or policy field keeps working for at least one minor release. It also prints a warning.
- **Agent skew.** Agents up to one minor version older than the control plane keep working.

---

## 4. Releases

### 4.1 What a release contains

goreleaser builds all of it from one tag:

| Artifact | Details |
|---|---|
| Binaries | linux, darwin and windows on amd64 and arm64, built with `CGO_ENABLED=0` |
| Checksums | `checksums.txt`, signed with cosign keyless signing |
| SBOM | One per archive and image, generated by syft |
| Container image | `ghcr.io/ulagsd/dbauthz`, multi-arch, distroless/static, non-root, signed |
| Helm chart | OCI chart on GHCR, signed |
| Provenance | SLSA build provenance |
| Packages | Homebrew tap, deb, rpm, apk, Scoop |
| Release notes | Generated from Conventional Commits and grouped by type |

### 4.2 Release steps

1. Confirm `main` is green and the milestone's issues are closed.
2. Write the highlights and upgrade notes, including every breaking change.
3. Tag from `main`. Use an annotated tag:
   ```bash
   git tag -a v0.1.0-alpha.1 -m "v0.1.0-alpha.1"
   git push origin v0.1.0-alpha.1
   ```
4. The release workflow runs goreleaser, signs everything and publishes.
5. Verify the published artifacts, as in section 4.3.
6. Announce the release.

**Never** move, delete or re-push a published tag. A broken release is fixed
by a new patch version.

### 4.3 Verifying a release

Each release must pass these checks:

- **Signatures.** Verify the signed checksums and the image signature with `cosign verify`.
- **Install.** Fresh installs work from the binary, Docker Compose and Helm.
- **Upgrade.** Upgrading from the previous release works, and migrations run cleanly.

### 4.4 Patch releases and hotfixes

- **Before v1.0.0,** fix on `main` and release the next patch from `main`.
- **From v1.0.0 onwards,** fix on `main` first. Then cherry-pick the fix to
  `release/vX.Y` with `git cherry-pick -x` and tag the patch from that branch.
  Never fix only on the release branch.
- **Security fixes** follow [SECURITY.md](../SECURITY.md). Prepare them in a
  private GitHub security advisory and publish the advisory with the release.

---

## 5. Distribution and upgrades

dbauthz is software that operators install. It is not a service we deploy, so
"deployment" here means how releases reach users and how they upgrade safely.

| Channel | Source |
|---|---|
| Binary and OS packages | GitHub Releases, Homebrew, apt/rpm/apk, Scoop |
| VM / EC2 / bare metal | Binary plus systemd unit plus `/etc/dbauthz/config.yaml` |
| Container | `ghcr.io/ulagsd/dbauthz:<version>` |
| Docker Compose | Quickstart file attached to each release |
| Kubernetes | Helm chart (OCI) and the operator |
| Air-gapped | Binary plus local PostgreSQL. Nothing calls the internet at runtime |

**Rules every release keeps:**
- **Pinned images.** Docs and examples pin an exact version. They never use `latest`.
- **Release notes cover upgrades.** Every release says whether migrations run, and whether the upgrade can be rolled back.
- **Store schema migrations** are ordered and reversible, as STACK.md section 5 requires. A migration that cannot be reversed is a breaking change.
- **Audit records survive every upgrade unchanged.** The hash chain must still verify after migration.

**TO DECIDE in the HLD:**
- **When migrations run.** Either automatically at startup or through an explicit `dbauthz migrate` step.
- **Replica upgrades.** How control-plane replicas upgrade without two schema versions writing at once.

---

## 6. For coding agents

Agents working in this repository also follow these rules:

- **Read before changing engine behaviour.** Read [reference.md](reference.md) before changing engine behaviour, and [STACK.md](STACK.md) before changing a dependency or tool.
- **Work on a branch.** Create a branch named as in section 2 before committing. Never commit directly to `main` once branch protection is on.
- **Commit only when asked.** Commit only when the maintainer asks, and never push, tag or release without an explicit request.
- **Format commits correctly.** Use Conventional Commits with `-s` sign-off, and add no AI attribution.
- **Run checks before reporting.** Run `make check` before reporting work as done, and report any failure with its output.
