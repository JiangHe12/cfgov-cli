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
