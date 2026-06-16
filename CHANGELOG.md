# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- P0 governance kernel: unified `cfgov.Backend` abstraction (`Coordinate{namespace,key}` → blob + revision/CAS) with a Nacos backend; Nacos `group/dataId` details are confined to the backend adapter.
- Commands: `ctx set/use/list/current`, `config get/push/delete`, `capabilities`, `audit query/verify`, `version`.
- `cfgclass` fail-closed config-write risk classifier (R0–R3) wired to `opskit-core` safety: protected-context escalation via `EffectiveRisk`, ticket gating at R2, and a precise `--allow-production-config-delete` allow flag at R3.
- Backend-bound contexts (`ctx set --backend nacos`) with `--backend` per-command override; credentials stored via `opskit-core` credstore.
- Audit trail records only content fingerprints (sha256) and byte counts — never plaintext config.
