# Changelog

All notable changes to this project are documented in this file.

## v0.5.13

### Changed

- Updated opskit-core to v1.1.4.

## v0.5.12

### Added
- Contract tests for JSON envelopes, JSON error output, plain version output, and success/error exit codes.

## v0.5.11

### Changed
- CLI-owned environment variables now prefer the family-standard `CFGOV_*` names: `CFGOV_AUDIT_PRIVATE_KEY`, `CFGOV_CREDENTIAL_PASSPHRASE`, `CFGOV_OPERATOR`, `CFGOV_DOWNLOAD_MIRROR`, and `CFGOV_SKIP_VERIFY`. Deprecated `CFGOV_CLI_*` aliases remain supported for compatibility.

## v0.5.10

### Changed
- **BREAKING**: `capabilities -o json` schema was restructured for family alignment; domain-specific fields moved to `data.domain`.

## v0.5.9

### Added
- Global flag: `--no-color`.

## v0.5.8

### Added
- `ctx migrate-credentials` subcommand for credential store migration.

## v0.5.7

### Changed
- Simplified `version -o plain` and `capabilities -o plain` output to the script-friendly family format.

## v0.5.6

### Changed
- Aligned root `--version` output with the family format by using the full CLI name.

## v0.5.5

### Changed
- Operation commands now show their target context/backend/server/namespace in table/plain output and JSON `data.target`.

## v0.5.4

### Changed
- Reuse opskit-core's shared secure-backend guard for stored credentials; behavior is unchanged.

## v0.5.3

### Added
- `ctx set --password` to store a Nacos password in a non-plain credstore backend
  (`keychain` / `encrypted-file`), matching the family credential posture.

### Fixed
- Nacos username/password can now be supplied without embedding credentials in
  the `--server` URL. `--username` plus `CFGOV_PASSWORD` (honored at command
  runtime when no credential is stored, for the current context and `--context`
  overrides), a stored credstore credential, or `--password` all work; precedence
  is explicit `--password`/`NACOS_PASSWORD` > stored credential > `CFGOV_PASSWORD`
  > `--server` URL userinfo. URL userinfo stays compatible (parsed out and not
  left on the URL). Non-Nacos backends are unchanged. Verified against real Nacos.

## v0.5.2

### Fixed
- `config list` against Apollo 2.x now returns items again. The Apollo adapter decoded the OpenAPI `/items` response as a flat JSON array, but Apollo 2.x returns a paged object (`{page, size, total, content}`), so every list failed with `failed to decode apollo item list`. `List` now decodes the paged envelope and pages through (`page`/`size`) until all `total` items are collected, with a guard that fails closed if pagination stalls. Single-item get/put/delete were unaffected. Verified against real Apollo 2.4.0.

## v0.5.1

### Fixed
- Nacos `public` namespace is now reachable by its name. Config, rule, flag and service operations bound to `--namespace public` previously queried a nonexistent tenant `public` and silently returned nothing (only an empty namespace reached the public tenant `""`). The api client now normalizes the reserved name `public` to the empty public tenant, so `--namespace public` works as users expect; non-public namespaces are unchanged.
- The `--backend` flag usage now lists `consul` alongside nacos, apollo, etcd and k8s.

## v0.5.0

### Added
- Kubernetes config watch: the `k8s` adapter now implements `Watch` (`config listen`) via the client-go watch API, with the same bounded single-shot long-poll contract as etcd/Consul — a change reports `Changed=true` with the object's new `resourceVersion`, a timeout/closed/bookmark reports `Changed=false` with the unchanged revision and no error, and a watch error is surfaced. Watch is object-granular (a per-object `FieldSelector`); the coordinate is fail-closed validated before any API call and Secret values never appear in the watch event or trace. `SupportsWatch` is now `true` for Kubernetes.
- Real-backend integration tests (`//go:build integration`, env-gated, skipped by default) for the etcd, Consul, Nacos and Kubernetes adapters, plus a nightly (and manually dispatchable) `Integration` workflow that starts live etcd/Consul/Nacos containers and a Kind cluster and runs them. Kept separate from the push/PR CI and the release pipeline so backend flakiness never blocks commits or releases.

## v0.4.0

### Added
- Consul backend (Axis-A 5th backend): a `consul` adapter implementing `cfgov.Backend` over Consul KV — coordinate `<keyPrefix><namespace>/<key>` with single-segment fail-closed validation, `ModifyIndex` CAS, watch via Consul blocking query (`config listen`), ACL token via credstore and optional TLS/mTLS (no insecure-skip-verify). History is NotImplemented.
- Consul rules + feature flags: Consul implements `cfgov.RuleStore` (rule sets at `<keyPrefix>SENTINEL/{app}-{type}-rules`, configurable via `--consul-rule-namespace`) and `cfgov.FlagStore` (`{app}-flags` under the bound namespace), so config + rules + flags all work on Consul.
- Consul service registry: Consul implements `cfgov.ServiceRegistry` (catalog + agent + health), making `service` a two-backend concern alongside Nacos. Instance health comes from real Consul health checks; instances are agent-registered with a deterministic `{service}-{ip}-{port}` id; Nacos-only group/cluster/ephemeral knobs are preserved as Consul service metadata rather than faked. `service register` is R1, `service deregister` is R2 → R3 protected with `--allow-production-service-deregister` (unchanged, backend-agnostic).

### Fixed
- Backend key validation (`validatePart` in the etcd and Consul adapters, and the Apollo equivalent) no longer trims before its content checks: leading/trailing whitespace is now rejected so the validated segment always equals the stored key.

## v0.3.0

### Added
- Feature flags: a new `flag` noun introducing feature flags as a second cfgov-native schema-over-backend typed policy alongside Sentinel rules. A flag set is one JSON-array config blob per app (`key`, `enabled`, `defaultVariant`, `variants`, percentage-rollout `rules`).
- `flag list/get/export/diff/validate` (R0 reads + shallow/deep validation) and `flag create/update/import/rollback` (R1) / `flag delete` (R2 → R3 protected + new `--allow-production-flag-delete`). Deep semantic checks (duplicate key, `rolloutPercent` out of 0–100, `defaultVariant`/rule `variant` integrity, enabled-without-variants warning) gate every non-delete write and cannot be bypassed by `--force` or `import`.
- Feature flags ride all four backends via the new optional `cfgov.FlagStore` interface (`Capabilities.SupportsFlags`): Nacos (group `FEATURE_FLAG_GROUP`, dataId `{app}-flags`), Apollo and etcd (key `{app}-flags` under the bound namespace), and Kubernetes (ConfigMap `{app}-flags`, data key `flags.json`). Each `FlagCoordinate` is fail-closed before any backend call. Flags reuse the shared governance kernel (backup-before-write, CAS, fingerprint-only audit, R0–R3 + protected escalation); the flag audit path uses the shared audit writer, so flag events carry ticket/reason and are queryable via `audit query --ticket`.

## v0.2.0

### Added
- Kubernetes rules-over-backend support: K8s now implements `cfgov.RuleStore` by storing Sentinel rule JSON arrays in ConfigMap data keys at `configmap/{app}-{type}-rules/rules.json` (ConfigMap/file-datasource convention, not a CRD datasource).
- Kubernetes config backend: `k8s` adapter for ConfigMap/Secret data keys (`configmap|secret/<name>/<dataKey>`) with kubeconfig context wiring, fail-closed coordinate validation, Secret-safe trace redaction, resourceVersion CAS, and honest `SupportsHistory=false` / `SupportsWatch=false` capability reporting.
- etcd rules-over-backend support: etcd now implements `cfgov.RuleStore`, deriving Sentinel rule coordinates as `{app}-{type}-rules` under a separate `etcdRuleNamespace` / `ETCD_RULE_NAMESPACE` override with default `SENTINEL`.
- etcd config backend: `cfgov.Backend` adapter with safe single-segment namespace/key mapping, CAS revisions, real watch support, TLS/mTLS connection options, context wiring, and honest `SupportsHistory=false` capability reporting.
- Rule deep-validation parity with sentinel-cli: ported the 5 cross-rule deep checks (`MULTIPLE_SYSTEM_RULES`, `FLOW_REFRESOURCE_MISSING` — ERROR; `PARAM_WITHOUT_FLOW`, `AUTHORITY_MIXED_STRATEGY`, `FLOW_DEGRADE_GRADE_MISMATCH` — WARNING) alongside the existing duplicate-key and dangerous-threshold checks. New `rule validate --dir <dir>` aggregates every `<type>.json` and runs the full cross-rule check set in one pass (`--file` XOR `--dir`). Single-file `rule validate --file --deep` now runs only intra-type checks (`IntraTypeDeepCheck`), so it no longer false-positives on cross-type rules; ERROR checks still block `rule create/update/import/rollback`.
- `config push --create-only` / `--update-only` (mutually exclusive): fail-if-exists (`RESOURCE_ALREADY_EXISTS`) / fail-if-not-found (`RESOURCE_NOT_FOUND`) semantics layered on the existing upsert as a post-authorization pre-write check; default `push` stays upsert, and CAS / backup / dry-run / audit / risk classification are unchanged.
- Local RBAC role management: `ctx role set/unset/list` write per-operator `reader`/`writer`/`admin` roles into the context (`reader`→R0, `writer`→R2, `admin`→R3 ceiling, enforced through `opskit-core/safety`); independent of the `--roles-source`/`--roles-url` remote role path.
- Convenience polish: `rule list --type` filter; `rule diff --dir` directory batch diff; `config listen` transient-error backoff (2s→60s, abort after 20 consecutive failures; auth failures still return immediately); `doctor` `auth` and `write-probe` checks (write-probe only confirms the governance write path / effective-risk is computable — never mutates a backend); `capabilities.supported.outputFormats`; bare parent commands now list their subcommands and mistyped subcommands keep closest-match suggestions.

### Fixed
- Embedded AI Skill (`skills/cfgov-cli/SKILL.md`): added the required YAML frontmatter (`name`/`description`/`allowed-tools`) — it was missing since v0.1.0, so agent skill loaders (e.g. cc-switch) rejected it with "missing YAML frontmatter delimited by ---" — and refreshed the documented backends to Nacos, Apollo, etcd, and Kubernetes.

## v0.1.0

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
- Context parity: `ctx set` exposes the remaining governance fields (`--env`, `--ticket-pattern`, `--roles-source`/`--roles-url`/`--allow-insecure-roles-url`, Vault `--vault-addr`/`--vault-path`/`--vault-role-id`/`--vault-secret-id`/`--vault-namespace`, per-context OTel `--otel-endpoint`/`--otel-metrics-endpoint`/`--otel-insecure`); new `ctx delete` (alias `remove`/`rm`), `ctx export`, `ctx import`, `ctx test`; `ctx`/`context` alias; `ctx list`/`current --show-secrets`. Security: `--vault-secret-id` is set only in the process `VAULT_SECRET_ID` (never persisted); credentials require a non-`plain-yaml` backend; `ctx export` redacts credentials by default and refuses cleartext export of credstore-backed secrets; `ctx import` needs `--force` to overwrite and `--yes` when non-interactive; `roles-url` must be https unless `--allow-insecure-roles-url`; `--show-secrets` is audited as a credential reveal.
- Platform parity: global `--context` (temporary context override, preserving the target context's protected/governance), `--debug`/`--trace`/`--trace-body-limit` (wired to the existing redacting backend trace), `--strict-no-change` (exit 13 when a plan has no changes), `--audit-max-size` (active-log rotation size), `--backup-keep` (backup retention). `audit prune` (rotated-log retention; `--before`/`--keep-last`, dry-run by default, `--confirm` to delete, and the prune itself is audited); `audit query` filters (`--context-filter`/`--namespace-filter`/`--protected`/`--ticket`/`--env`/`--data-id`/`--app`/`--group`/`--rule-type`/`--path`/`--resource`) and `audit query`/`verify` table/plain output; `audit verify --path`/`--strict`/`--confirm`/`--decrypt`. `capabilities` now self-reports the bound backend's real capabilities plus limits/features; Apollo no longer lists a phantom `rule` verb and Nacos advertises the `rule` resource type.
- Operational parity: `service register`/`deregister` now enforce the same backup-policy decision as config writes (protected contexts require explicit `--backup`/`--no-backup`), and `register` warns on stderr when registering an ephemeral instance. Idempotent no-op writes are detected after authorization and recorded as `skipped` audit events (fingerprint-only): `config push` and `rule create/update/import` skip the backend write when the remote content already matches, and `config import/promote/reconcile` audit already-matching items as skipped. New `backup list`/`backup clean` local-store maintenance (`clean` mirrors `audit prune`: `--before`/`--keep-last`, dry-run by default, `--confirm` to delete, and the clean itself is audited). `namespace delete` adds a human y/N confirmation after authorization (skipped by `--yes`/`--non-interactive`; never replaces the R2/R3 authorization gate).
- Ops/UX parity: read-only `doctor` diagnostics (context/backend-ping/audit-log-writability; all output redacted, self-audited, no backend mutation); OpenTelemetry command spans plus trace/metrics exporter shutdown-flush (span/metric attributes carry only safe metadata — operator, context, env, ticket, protected — never config/rule content or credentials); `completion {bash|zsh|fish|powershell}`; "did you mean" suggestions on mistyped commands; command aliases (`list`→`ls`, `delete`→`del`/`rm`) and short flags (`config -f/-g/-q`, `service -s`); `rule validate --fail-on-warnings` (non-zero exit when deep validation reports warnings); `rule get --resource` (display-only exact-match filter on the rule `resource` field — audit still records the full rule set). `capabilities` no longer advertises `backup clean` as an R-tier verb (it is a `--confirm`/dry-run local-maintenance op like `audit prune`); `DoctorResult` added to the kind list.
