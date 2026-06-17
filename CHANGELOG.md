# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- P0 governance kernel: unified `cfgov.Backend` abstraction (`Coordinate{namespace,key}` → blob + revision/CAS) with a Nacos backend; Nacos `group/dataId` details are confined to the backend adapter.
- Commands: `ctx set/use/list/current`, `config get/push/delete`, `capabilities`, `audit query/verify`, `version`.
- `cfgclass` fail-closed config-write risk classifier (R0–R3) wired to `opskit-core` safety: protected-context escalation via `EffectiveRisk`, ticket gating at R2, and a precise `--allow-production-config-delete` allow flag at R3.
- Backend-bound contexts (`ctx set --backend nacos`) with `--backend` per-command override; credentials stored via `opskit-core` credstore.
- Audit trail records only content fingerprints (sha256) and byte counts — never plaintext config.
- Single-config read verbs: `config list/diff/validate/pull/history/listen` (`diff` reports only sha256 + line deltas; `listen` is a bounded, cancellable long-poll).
- Local backup primitive with backup-before-write enforcement on `config push/delete`: `--backup`/`--no-backup` + `safety.ValidateBackupPolicy`; protected contexts require an explicit backup decision; the destructive write aborts if the backup fails; backups store under `~/.cfgov-cli/backups` and audit records only the backup id + sha256.
- `cfgov.Backend` extended with `History` and `Watch` (capability-gated via `supportsHistory`/`supportsWatch`); config keys reject `.`/`..` path-traversal segments and backup paths encode them.
- Config write-class verbs: `config export/import/promote/rollback/reconcile`; batch plans expose create/update/delete/prune counts and key lists, rollback supports local backup files/ids or Nacos history, and reconcile prune requires the precise `--allow-production-prune` R3 allow flag.
- Nacos namespace and service parity verbs via separate capability interfaces: `namespace list/create/update/delete` and `service list/get/instances/register/deregister`; destructive verbs require precise `--allow-production-namespace-delete` / `--allow-production-service-deregister` flags at R3.
- Sentinel rule schema-over-backend read kernel: `rule list/get/export/diff/validate` reads rule sets as config blobs via derived Nacos coordinates, validates flow/degrade/system/authority/param schemas, and reports only sha256/count metadata in audit.
- Governed Sentinel rule writes: `rule create/update/import/delete/rollback` persist rule arrays through the config backend with CAS, mandatory deep validation, backup-before-overwrite/delete, and the single R3 `--allow-production-rule-delete` flag for protected deletes.
- Apollo config backend adapter: cfgov can now bind contexts to Apollo OpenAPI for config get/list/push/delete with item-level coordinate mapping, CAS revisions, release publishing, and honest NotImplemented gates for unsupported history/watch/rule/service capabilities.
- Apollo RuleStore support: Sentinel rule commands now work against Apollo with sentinel-compatible item keys (`{app}-{type}-rules`) and a separate default rule namespace of `SENTINEL`.
- `cfgov install <agent> --skills`: installs the embedded cfgov AI Skill into an agent's skills directory (claude/codex/opencode/copilot/cursor/cc-switch/windsurf/aider or a custom path), writes an `.installed-by` manifest, and verifies the copy.
- npm distribution: `package.json` (unscoped `cfgov-cli`), `bin/cfgov-cli.js` launcher, and `scripts/install.js` postinstall that downloads the platform binary from the signed GitHub Release with SHA-256 verification and a redirect-host allowlist; `release.yml` tag pipeline (multi-platform build, cosign signing, checksums, GitHub Release, npm publish via OIDC).
- Backend-agnostic config key validation: `cfgov.Backend.ValidateKey` (Nacos `group/dataId` rules vs Apollo item-key rules); backup identity is backend-adapted; `ParseNacosKey` rejects any `.`/`..` path segment (split on `/` and `\`).
- Config flag parity with nacos-cli: `diff`/`validate`/`push --content` (mutually exclusive with `--file`), `push --no-validate` (skips only content-format validation, never governance), `validate`/`push --type xml`, `list --query/-q`; `import --skip-existing/--overwrite/--validate/--force-large-import`, `reconcile --prune-scope/--overwrite/--force-large-reconcile`, `rollback --validate`, `promote --validate/--overwrite/--type`; `diff --source-context/--target-context` cross-context comparison with LCS line-level output. `--force-large-*` lifts only the change-count ceiling, never the cfgclass/authorize/backup gates; `--prune` now requires an explicit `--prune-scope`.
