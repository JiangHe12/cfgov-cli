---
name: cfgov-cli
description: Governed configuration, Sentinel rule, and feature-flag operations across Nacos, Apollo, etcd, Kubernetes, and Consul with R0-R3 authorization, backup-before-write, redaction, and fingerprint-only audit.
allowed-tools: Bash(cfgov:*), Bash(cfgov-cli:*)
---

# cfgov-cli

Use `cfgov` for governed configuration operations across Nacos, Apollo, etcd, Kubernetes, and Consul. It wraps reads, writes, backups, audit, and R0-R3 authorization for config blobs, Sentinel rule sets, and feature-flag sets.

## Hard Rules For AI Agents

- Prefer `-o json` for machine parsing.
- Never invent or self-fill `--ticket`, `--allow-*`, or high-risk `--yes`. These are human authorization inputs.
- Blast radius must come from `cfgov` itself via `--dry-run`, `--plan`, or `--diff`; do not guess impact from model reasoning.
- R0 reads are audited. R1 requires `--yes`. R2 requires `--yes` and a non-empty `--ticket`. R3 requires those plus the exact `--allow-*` flag.
- Protected contexts raise the effective risk by one tier through opskit-core safety.
- Audit records metadata, revisions, counts, and sha256 fingerprints; never put raw configuration or rule bodies into tickets, reasons, or summaries.
- Authorization and audit identity comes only from the local OS username plus hostname. The legacy root `--operator`, `CFGOV_OPERATOR`, and `CFGOV_CLI_OPERATOR` inputs are deprecated and ignored; `audit query --operator` is only a record filter.
- This identity rule does not separate an AI process from a human using the same OS account. That boundary requires externally verified approval or a separate OS identity.

## Contexts And Backends

Create and select contexts with:

```bash
cfgov ctx set <name> --backend nacos --server <url> --namespace <namespace> [--username <user>] [--protected] --plan -o json
cfgov ctx set <name> --backend apollo --server <url> --apollo-app-id <appId> --apollo-env <env> --apollo-cluster <cluster> --apollo-namespace <namespace> [--apollo-rule-namespace SENTINEL] [--protected] --plan -o json
cfgov ctx set <name> --backend etcd --server <host:port,host:port> [--etcd-key-prefix <prefix>] [--etcd-rule-namespace SENTINEL] [--namespace <namespace>] [--etcd-ca-cert <path>] [--etcd-client-cert <path>] [--etcd-client-key <path>] [--protected] --plan -o json
cfgov ctx set <name> --backend k8s [--k8s-kubeconfig <path>] [--k8s-context <ctx>] --namespace <k8s-namespace> [--protected] --plan -o json
cfgov ctx set <name> --backend consul --server <host:port> [--consul-key-prefix <prefix>] [--consul-rule-namespace SENTINEL] [--namespace <namespace>] [--consul-ca-cert <path>] [--consul-client-cert <path>] [--consul-client-key <path>] [--protected] --plan -o json
cfgov ctx use <name> --plan -o json
cfgov ctx list -o json
cfgov ctx current -o json
cfgov ctx role set <name> --target-operator <operator> --role reader|writer|admin --yes --ticket <ticket> --allow-role-change
cfgov ctx role list <name> -o json
cfgov ctx migrate-credentials --dry-run
cfgov ctx migrate-credentials --yes --ticket <ticket> --allow-context-change
```

Every `ctx set`/`ctx use` line above is a preview. To apply the reviewed command, rerun the exact command with `--plan` replaced by `--yes --ticket <human-ticket> --allow-context-change`. Never supply those human-approval values yourself.

Context create/replace/switch/import/credential migration is always R3 with `--allow-context-change`; context deletion is R3 with `--allow-context-delete`; role set/unset is R3 with `--allow-role-change`. Existing set/import targets authorize against their own pre-change protected/RBAC policy. A new target uses the persisted current context's pre-change policy, or an empty bootstrap policy when no current context exists. `ctx use` authorizes against the old persisted current policy, falling back to the target policy only when no current context exists. Every apply path re-reads and authorizes its pre-change policy inside the context-file lock; credential migration authorizes the complete locked batch before its first credential write. Preview modes return before authorization and perform no target mutation. Portable context import accepts exactly one YAML document, rejects unknown fields, and validates credential backend availability, `ticketPattern` syntax, and inline `reader`/`writer`/`admin` roles without writing credentials.

For authenticated Nacos, prefer `--username <user>` in the context and `CFGOV_PASSWORD` at command runtime when no credential is stored. To persist a password, use `ctx set --password <password> --credential-backend keychain|encrypted-file`. `--server http://user:pass@host:8848` remains supported, but explicit `--password` or `CFGOV_PASSWORD` takes precedence over URL userinfo.

`ctx set --plan` still loads and validates the context configuration and verifies that the selected credential backend exists and is available. It does not write the context or credential store.

`--backend` can temporarily override the current context for one command. Nacos supports config, rule, feature flag, namespace, service, config history, and config listen. Apollo supports config, rule, and feature-flag storage; namespace/service management, history, and listen are not supported and fail closed. etcd supports config, rule, and feature-flag storage plus native watch (`config listen`); history, namespace, and service are not supported. Kubernetes (ConfigMap/Secret) supports config, rule, and feature-flag storage plus object-granular watch (`config listen`) — config keys are `<kind>/<name>/<dataKey>` where `<kind>` is `configmap` or `secret`, rule sets use ConfigMap keys `configmap/{app}-{type}-rules/rules.json` in the context `--namespace`, and namespace/service plus history are not supported and fail closed. Kubernetes exec credential plugins are rejected fail-closed because client-go connects plugin stderr directly to the process; use a static bearer token or client certificate in the selected kubeconfig context. Consul supports config, rule, and feature-flag storage plus service registry and watch via blocking query (`config listen`); namespace and history are not supported and fail closed. Always check `cfgov capabilities -o json` for the bound backend.

Nacos and Apollo report `supportsCas=false`. They can read rule/flag blobs and
create a missing blob, but an update, delete, rollback, or import that would
modify an existing rule/flag blob returns `NOT_IMPLEMENTED` before
authorization, backup, audit intent, or target mutation. Check
`supportsExistingRuleWrites` / `supportsExistingFlagWrites`; never remove the
revision binding or retry as an unconditional write.

Credentials are stored through cfgov context credential handling. Hidden token/secret flags exist for setup paths; do not print secrets.

## Config

R0 read operations:

```bash
cfgov config get --key <dataId-or-group/dataId> -o json
cfgov config list [--group <group>] [--prefix <prefix>] [--page 1 --page-size 20] -o json
cfgov config diff --key <key> --file <path> -o json
cfgov config validate --file <path> [--type text|properties|json|yaml] -o json
cfgov config pull --key <key> --file <path> -o json
cfgov config history --key <key> [--page 1 --page-size 20] -o json
cfgov config listen --key <key> [--max-events 1] [--long-poll 30s] -o json
cfgov config export --dir <dir> [--group <group>] [--prefix <prefix>] [--limit 1000] -o json
```

An externally canceled `config listen` exits nonzero; treat it as incomplete rather than success.

Write operations:

```bash
cfgov config push --key <key> --file <path> [--type text|properties|json|yaml|xml] [--expected-revision <rev>] --dry-run --diff -o json
cfgov config push --key <key> --file <path> --yes --backup -o json
cfgov config delete --key <key> [--expected-revision <rev>] --dry-run --diff -o json
cfgov config delete --key <key> --yes --ticket <ticket> [--allow-production-config-delete] --backup -o json
cfgov config import --dir <dir> --dry-run --plan -o json
cfgov config promote --source-context <ctx> (--key <key>|--prefix <prefix>) --dry-run --diff -o json
cfgov config rollback --key <key> (--backup-file <file>|--backup-id <id>|--history-id <id>) --dry-run --diff -o json
cfgov config reconcile --dir <dir> [--allow-production-reconcile] [--prune --allow-production-prune] --dry-run --plan -o json
```

Risk model: `push`, `import`, `promote`, and `rollback` are R1; `delete` is R2 and protected delete becomes R3 with `--allow-production-config-delete`; `reconcile` without prune is R2 and protected-context escalation requires `--allow-production-reconcile`, while `--prune` is R3 with `--allow-production-prune`.

`--plan` is a hard target no-mutation override for both backend writes and local mutations (contexts/RBAC/credentials, pull/export, audit repair/prune, backup cleanup, and skill installation). It wins over `--confirm`; command-local `--dry-run` flags and write-command `--diff` paths that return `ChangePlan` are also previews. Every successfully completed preview emits exactly one `command.preview` audit event with `status=skipped`, `preview=true`, and `dryRun=true`; failure to append it fails the command. The governed audit log, including resource-read records for reads that actually occurred, is the only permitted local mutation.

Backend-backed R0 resource reads are fail-closed. A `ReadAuditRecord` intent must be durable before backend client construction or any other backend access, and its outcome with the same `operationId` must be durable before any result or file content is released. After intent and before construction, enforce R0 roles for every involved context; unknown operators and configured remote role sources fail closed and receive an outcome. Intent failure prevents backend construction; outcome failure withholds the result and returns `LOCAL_IO_ERROR`, preserving a backend error in the cause chain when both fail. Backend and credential-store reads used by config, rule, flag, namespace, and context write-plan/apply preflight follow the same rule. Construct clients only from the exact authorized context snapshot; a later context-file change must not redirect the operation. A mutation with no remote preflight must complete elevated authorization and persist its mutation intent before client construction. Batch reads and one bounded `config listen` each use one pair; reject `--max-events` above 1000 before allocation. Resource-specific audit metadata contains fingerprinted targets/requests and bounded counts, never returned bodies or resource lists. Local validation, static `capabilities` / `version`, and dry-runs that do not access a backend are excluded. Check `supported.readAudit = "required-intent-outcome"` and `limits.maxListenEvents = 1000` in `cfgov capabilities -o json`.

`config export`, `rule export`, and `flag export` are create-only. Generated names and every destination path are preflighted before the mutation intent; collisions fail in plan and apply mode, and apply uses exclusive creation so existing files are never overwritten.

Every actual target mutation synchronously persists a `MutationAuditRecord` intent after authorization/final validation and before the first target write, then an outcome before ordinary success. Batch operations use one pair with aggregate counts. Core v2 commit state is authoritative: only known-not-committed outcomes enter the owner-only, fsynced `<audit.log>.outcome-spool`; committed-post-commit-error and indeterminate outcomes are not blindly queued. An indeterminate replay is renamed with `.indeterminate` and blocks later automatic replay. Every incomplete path returns `AUDIT_INCOMPLETE`; reconcile by `mutationId + phase` before any manual recovery.

Audit and telemetry contain no raw ticket, reason, config/rule/flag body, or full error text. Use the domain-separated SHA-256 fingerprints, byte/item/revision metadata, and machine error code. Historical audit query output blanks legacy ticket/reason/diff/error-message values.

`doctor --plan` marks the audit write check as `skipped` and returns `complete=false`; it does not claim that audit-log writability was verified.

Use `--backup` or `--no-backup` according to policy. Protected destructive writes require an explicit backup decision. Overwrite/delete paths back up current remote content before mutation when backup is required.

## Sentinel Rules

Rule types are `flow`, `degrade`, `system`, `authority`, and `param`. Rule storage is schema-over-backend config: Nacos uses `SENTINEL_GROUP` and dataId `{app}-{type}-rules`; Apollo uses item key `{app}-{type}-rules` in rule namespace `SENTINEL` by default; etcd uses key `<keyPrefix><ruleNamespace>/{app}-{type}-rules` with rule namespace `SENTINEL` by default; Consul uses key `<keyPrefix><ruleNamespace>/{app}-{type}-rules` with rule namespace `SENTINEL` by default; Kubernetes uses ConfigMap data key `configmap/{app}-{type}-rules/rules.json` in the context namespace. The Kubernetes convention is for ConfigMap/file-datasource consumption, not a Sentinel CRD datasource.

R0 read and validation:

```bash
cfgov rule list --app <app> [--type <type>] -o json
cfgov rule get --app <app> --type <flow|degrade|system|authority|param> -o json
cfgov rule export --app <app> --dir <dir> -o json
cfgov rule diff --app <app> --type <type> --file <path> -o json
cfgov rule diff --app <app> --dir <dir> -o json
cfgov rule validate --file <path> [--deep] -o json
cfgov rule validate --dir <dir> --deep [--fail-on-warnings] -o json
```

Write operations:

```bash
cfgov rule create --app <app> --type <type> --file <path> [--force] [--expected-revision <rev>] --dry-run --diff -o json
cfgov rule update --app <app> --type <type> --file <path> [--expected-revision <rev>] --dry-run --diff -o json
cfgov rule import --app <app> --from-dir <dir> --dry-run --plan -o json
cfgov rule rollback --app <app> --backup <ref> --dry-run --diff -o json
cfgov rule delete --app <app> --type <type> (--resource <resource>|--all) [--expected-revision <rev>] --dry-run --diff -o json
```

Risk model: `create`, `update`, `import`, and `rollback` are R1; `delete` is R2 and protected delete becomes R3 with `--allow-production-rule-delete`.

Every rule write must pass shallow JSON/schema validation before authorization. Create, update, import, and rollback also run deep semantic checks; deep errors cannot be bypassed by flags. `rule validate --file --deep` is intra-rule validation for one isolated rule type; use `rule validate --dir --deep` for cross-rule checks across flow/degrade/system/authority/param files. Rule overwrite/delete/rollback paths back up the existing remote rule set before writing.

## Feature Flags

Feature flags are a cfgov-native typed policy stored as one JSON-array config blob per app, on every backend: Nacos group `FEATURE_FLAG_GROUP` dataId `{app}-flags`; Apollo, etcd, and Consul use key `{app}-flags` under the bound namespace; Kubernetes uses ConfigMap `{app}-flags` data key `flags.json` in the context namespace. A flag has `key`, `enabled`, optional `description`/`defaultVariant`, `variants` (`{name,value}`), and percentage-rollout `rules` (`{variant,rolloutPercent,segment}`).

R0 read and validation:

```bash
cfgov flag list --app <app> -o json
cfgov flag get --app <app> [--key <key>] -o json
cfgov flag export --app <app> --dir <dir> -o json
cfgov flag diff --app <app> (--file <path>|--dir <dir>) -o json
cfgov flag validate (--file <path>|--dir <dir>) [--deep] [--fail-on-warnings] -o json
```

Write operations:

```bash
cfgov flag create --app <app> --file <path> [--force] [--expected-revision <rev>] --dry-run --diff -o json
cfgov flag update --app <app> --file <path> [--expected-revision <rev>] --dry-run --diff -o json
cfgov flag import --app <app> (--file <path>|--dir <dir>) --dry-run --plan -o json
cfgov flag rollback --app <app> --backup <ref> --dry-run --diff -o json
cfgov flag delete --app <app> (--key <key>|--all) [--expected-revision <rev>] --dry-run --diff -o json
```

Risk model: `create`, `update`, `import`, and `rollback` are R1; `delete` is R2 and protected delete becomes R3 with `--allow-production-flag-delete`. Create, update, import, and rollback run deep semantic checks (duplicate key, `rolloutPercent` out of 0-100, `defaultVariant`/rule `variant` must exist) that flags cannot bypass; `delete` requires `--key` or `--all`. Overwrite/delete/rollback paths back up the existing remote flag set first.

## Namespace

Namespace commands are Nacos-only. Apollo, etcd, and Kubernetes return NotImplemented.

```bash
cfgov namespace list -o json
cfgov namespace create --id <id> --name <name> [--desc <desc>] --dry-run --plan -o json
cfgov namespace update --id <id> --name <name> [--desc <desc>] --dry-run --plan -o json
cfgov namespace delete --id <id> --dry-run --plan -o json
```

Risk model: `list` is R0; `create` and `update` are R1; `delete` is R2 and protected delete becomes R3 with `--allow-production-namespace-delete`. Delete plans include namespace config count from the backend.

## Service

Service registry commands work on Nacos and Consul. Apollo, etcd, and Kubernetes return NotImplemented. On Consul, instances are agent-registered with a deterministic `{service}-{ip}-{port}` id, health comes from real Consul checks, and the Nacos-only group/cluster/ephemeral knobs are preserved as Consul service metadata (not faked).

```bash
cfgov service list [--page 1 --page-size 20] -o json
cfgov service get --service <name> -o json
cfgov service instances --service <name> [--group <group>] -o json
cfgov service register --service <name> --ip <ip> --port <port> [--group <group>] [--cluster <cluster>] [--weight <n>] [--metadata k=v] [--persistent|--ephemeral] --dry-run --plan -o json
cfgov service deregister --service <name> --ip <ip> --port <port> [--group <group>] [--cluster <cluster>] --dry-run --plan -o json
```

Risk model: read commands are R0; `register` is R1; `deregister` is R2 and protected deregister becomes R3 with `--allow-production-service-deregister`.

## Audit, Capabilities, Version

```bash
cfgov capabilities -o json
cfgov backup list [--context-filter <ctx>] [--namespace <ns>] [--data-id <key>] -o json
cfgov backup clean (--before <30d|rfc3339|yyyy-mm-dd>|--keep-last <n>) -o json
cfgov backup clean (--before <30d|rfc3339|yyyy-mm-dd>|--keep-last <n>) --confirm --yes --ticket <ticket> --allow-backup-clean -o json
cfgov audit query [--since 24h] [--until <rfc3339>] [--type <type>] [--operator <name>] [--context-filter <ctx>] [--status <status>] [--limit 100] -o json
cfgov audit verify [--strict] -o json
cfgov audit verify --repair --confirm --yes --ticket <ticket> --allow-audit-repair -o json
cfgov audit prune (--before <30d|rfc3339|yyyy-mm-dd>|--keep-last <n>) -o json
cfgov audit prune (--before <30d|rfc3339|yyyy-mm-dd>|--keep-last <n>) --confirm --yes --ticket <ticket> --allow-audit-prune -o json
cfgov version -o json
cfgov install <agent> --skills
```

`backup clean` and `audit prune` default to dry-run. Confirmed backup cleanup is a fixed R3 mutation requiring `--confirm`, `--yes`, a non-empty human ticket, and `--allow-backup-clean`. Confirmed audit pruning and repair are fixed R3 evidence mutations requiring the equivalent inputs and the exact `--allow-audit-prune` or `--allow-audit-repair`. All authorize against the persisted current-context policy (empty only when no current context exists), never a `--context` override. Preview returns before authorization and does not change the target. Core v2 holds the audit-path lock for evidence pruning/repair, binds confirmation to the exact preview set, fully verifies history, and returns `CONFLICT` if that set changed. Pruning supports authenticated v2 history and advances its checkpoint before deletion; repair remains legacy-only. Audit prune/repair write control evidence to the sibling `.<audit-base>-control` log. Nacos trace never contains request/response bodies and its public errors never echo remote bodies; TLS verification cannot be disabled by an environment variable. Vault credential backends require an absolute HTTPS address without userinfo, query, or fragment. Do not add confirmation or authorization inputs unless the human explicitly supplied them after reviewing the preview.

Check `cfgov capabilities -o json` before assuming a backend supports a noun or verb.
