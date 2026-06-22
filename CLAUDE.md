# cfgov-cli Agent Guide

This file is the contributor and AI-agent guide for this repository.
`CLAUDE.md` and `AGENTS.md` are kept identical; edit both together.
The workspace `../CLAUDE.md` (opskit family guide) and the global
`~/.claude/CLAUDE.md` rules also apply and take precedence.

## Project Summary

cfgov-cli is the governed config, rule, and feature-flag operations CLI for AI
agents: one entry point for application configuration, Sentinel flow-control
rules, and feature flags across
**Nacos**, **Apollo**, **etcd**, and **Kubernetes**. It provides backend-bound contexts, a fail-closed
config-write risk classifier (`cfgclass`), R0-R3 authorization with
protected-context escalation, backup-before-write + rollback, tamper-evident
fingerprint-only audit, and redaction. It is built on the shared `opskit-core`
engine and supersedes the deprecated nacos-cli and sentinel-cli.

## Working Discipline (how to work in this repo)

- Implement the task's goal within its stated boundaries. Do not invent scope,
  features, abstractions, or "future-proofing" nobody asked for.
- Make the smallest change that solves it; match surrounding style; remove any
  new unused imports/vars/flags you introduce.
- Never weaken governance, security, authorization, redaction, or audit to make
  code or a test pass. If a test seems to require that, the test is wrong.
- Do not modify `opskit-core`; consume its published APIs.
- Do not add design/spec/plan docs to the repo — change history lives in git.
- A change is complete only after ALL Build & Verify gates pass. Report the real
  results; never claim "should pass".

## Build & Verify (every gate must be green before "done")

```bash
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal           # must print nothing
golangci-lint run --timeout=5m
go vet -tags=integration ./...          # integration-tagged files are skipped otherwise
CGO_ENABLED=1 go test -race -count=1 ./...
```

- README / SKILL.md command examples are NOT covered by CI: run the real binary
  and confirm every cited flag exists (`cfgov <cmd> --help`) before shipping docs.
- A new `t.Parallel()` test must not mutate a process global (config path, env,
  `os.Stdout`); that races and only the Linux `-race` CI job catches it.

## Governance Rules (non-negotiable)

- R0 reads are free but audited. R1 needs `--yes`. R2 also needs a non-empty
  `--ticket`. R3 also needs the exact command-specific `--allow-*` flag.
- Protected contexts raise every operation one tier; authorization must go
  through `opskit-core/safety` (`EffectiveRisk` + `Authorize`).
- `cfgclass` is the only config-write risk source and must stay fail-closed and
  structure-aware: unknown/uncertain inputs escalate, never fall to R0.
- Rule writes pass shallow validation; create/update/import/rollback also run
  deep semantic checks that no flag may bypass. Rules are schema-over-backend — a
  rule set is one config blob via the existing Backend; do not add a Backend method.
- Feature flags are a second schema-over-backend typed policy with the same
  deep-check-gated writes (create/update/import/rollback); `FlagStore` is a
  separate optional interface, not a new Backend method.
- Destructive writes back up current remote content first and abort if backup
  fails; protected contexts require an explicit `--backup`/`--no-backup`.
- AI agents never auto-fill `--ticket`, `--allow-*`, or a high-risk `--yes`.
  Blast radius comes from `--dry-run`/`--plan`/`--diff`, never a model guess.
- Audit stores only metadata, sha256 fingerprints, and counts — never raw config
  or rule bodies, tickets, or reasons. Redaction applies before caller output and
  before audit persistence.
- Backend-specific addressing (Nacos group/dataId; Apollo app/env/cluster/item;
  etcd key-prefix/namespace segments; K8s `configmap|secret/<name>/<dataKey>`)
  stays inside the adapter. Unsupported capabilities fail closed (e.g. Apollo
  namespace/service/history/listen, etcd namespace/service/history, K8s
  namespace/service/history/watch → NotImplemented), never silently degrade.

## Code Conventions

- `cmd/` uses `apperrors.New`; bare `fmt.Errorf`/`errors.New` are forbidden there
  (forbidigo CI guard) and exit codes come from the `apperrors` contract.
- Reuse opskit-core for contexts, credentials, safety, audit, printing,
  redaction, telemetry, errors, and lockfile — never reimplement them.
- New backends implement `cfgov.Backend`; optional capabilities use the separate
  `RuleStore` / `FlagStore` / `NamespaceManager` / `ServiceRegistry` interfaces,
  type-asserted and capability-gated.
- Add focused table-driven and adversarial tests for security-sensitive changes;
  do not weaken production behavior for tests.
- Keep `.gitattributes` (`eol=lf`) so the Windows lint job does not fail gofmt on
  a CRLF checkout.

## Repository Layout

- `cmd/` - Cobra commands and `-o json` output contracts
- `internal/backend/{nacos,apollo,etcd,k8s}` - backend adapters
- `internal/cfgov` - Backend abstraction + coordinate/key handling
- `internal/cfgclass` - fail-closed config-write classifier
- `internal/rule` - Sentinel rule schemas + shallow/deep validation
- `internal/flag` - feature-flag schema + shallow/deep validation
- `internal/backup` · `internal/cfgovctx` · `internal/api` - backup store, contexts, HTTP
- `skills/cfgov-cli/` - embedded AI Skill (keep in sync with the real flags)
- `bin/` · `scripts/` · `.github/workflows/` - npm shim, installer, CI/release

## Release & Versioning (maintainer-owned — do not initiate)

Releases are cut by the maintainer only; do not tag, publish, or edit artifacts.

**Docs-before-release gate (mandatory).** A release ships only after every
user-facing doc already matches the code's actual state — `README.md`,
`README_zh.md`, `skills/cfgov-cli/SKILL.md`, this guide (`CLAUDE.md`/`AGENTS.md`),
and the `package.json` description. Any new backend, noun/verb, flag, risk tier,
or dependency / Go-version bump must be reflected first (confirm examples with
`cfgov <cmd> --help`). Code must never ship ahead of its docs; a release carrying
stale docs is incomplete — align the docs, then cut the release.

For reference, a release bumps `package.json`, adds an exact `## vX.Y.Z`
`CHANGELOG.md` heading, passes Build & Verify (`npm pack --dry-run` lists exactly
`LICENSE`, `README.md`, `package.json`, `bin/cfgov-cli.js`, `scripts/install.js`),
then pushes tag `vX.Y.Z`. **npm publish is locked to the CI trusted publisher via
OIDC; local/token `npm publish` is disabled — never attempt a manual publish.**
