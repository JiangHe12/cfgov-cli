---
name: cfgov-cli
description: Governed configuration and Sentinel rule operations across Nacos, Apollo, etcd, and Kubernetes with R0-R3 authorization, backup-before-write, redaction, and fingerprint-only audit.
allowed-tools: Bash(cfgov:*), Bash(cfgov-cli:*)
---

# cfgov-cli

Use `cfgov` for governed configuration operations across Nacos, Apollo, etcd, and Kubernetes. It wraps reads, writes, backups, audit, and R0-R3 authorization for config blobs and Sentinel rule sets.

## Hard Rules For AI Agents

- Prefer `-o json` for machine parsing.
- Never invent or self-fill `--ticket`, `--allow-*`, or high-risk `--yes`. These are human authorization inputs.
- Blast radius must come from `cfgov` itself via `--dry-run`, `--plan`, or `--diff`; do not guess impact from model reasoning.
- R0 reads are audited. R1 requires `--yes`. R2 requires `--yes` and a non-empty `--ticket`. R3 requires those plus the exact `--allow-*` flag.
- Protected contexts raise the effective risk by one tier through opskit-core safety.
- Audit records metadata, revisions, counts, and sha256 fingerprints; never put raw configuration or rule bodies into tickets, reasons, or summaries.

## Contexts And Backends

Create and select contexts with:

```bash
cfgov ctx set <name> --backend nacos --server <url> --namespace <namespace> [--protected]
cfgov ctx set <name> --backend apollo --server <url> --apollo-app-id <appId> --apollo-env <env> --apollo-cluster <cluster> --apollo-namespace <namespace> [--apollo-rule-namespace SENTINEL] [--protected]
cfgov ctx set <name> --backend etcd --server <host:port,host:port> [--etcd-key-prefix <prefix>] [--etcd-rule-namespace SENTINEL] [--namespace <namespace>] [--etcd-ca-cert <path>] [--etcd-client-cert <path>] [--etcd-client-key <path>] [--protected]
cfgov ctx set <name> --backend k8s [--k8s-kubeconfig <path>] [--k8s-context <ctx>] --namespace <k8s-namespace> [--protected]
cfgov ctx use <name>
cfgov ctx list -o json
cfgov ctx current -o json
cfgov ctx role set <name> --target-operator <operator> --role reader|writer|admin
cfgov ctx role list <name> -o json
```

`--backend` can temporarily override the current context for one command. Nacos supports config, rule, namespace, service, config history, and config listen. Apollo supports config and rule storage; namespace/service management, history, and listen are not supported and fail closed. etcd supports config and rule storage plus native watch (`config listen`); history, namespace, and service are not supported. Kubernetes (ConfigMap/Secret) supports config only — keys are `<kind>/<name>/<dataKey>` where `<kind>` is `configmap` or `secret`, the context `--namespace` is the Kubernetes namespace, and rule/namespace/service, history, and watch are not supported and fail closed. Always check `cfgov capabilities -o json` for the bound backend.

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

Write operations:

```bash
cfgov config push --key <key> --file <path> [--type text|properties|json|yaml] [--expected-revision <rev>] --dry-run --diff -o json
cfgov config push --key <key> --file <path> --yes --backup -o json
cfgov config delete --key <key> [--expected-revision <rev>] --dry-run --diff -o json
cfgov config delete --key <key> --yes --ticket <ticket> [--allow-production-config-delete] --backup -o json
cfgov config import --dir <dir> --dry-run --plan -o json
cfgov config promote --source-context <ctx> (--key <key>|--prefix <prefix>) --dry-run --diff -o json
cfgov config rollback --key <key> (--backup-file <file>|--backup-id <id>|--history-id <id>) --dry-run --diff -o json
cfgov config reconcile --dir <dir> [--prune] --dry-run --plan -o json
```

Risk model: `push`, `import`, `promote`, and `rollback` are R1; `delete` is R2 and protected delete becomes R3 with `--allow-production-config-delete`; `reconcile` without prune is R2, while `--prune` is R3 with `--allow-production-prune`.

Use `--backup` or `--no-backup` according to policy. Protected destructive writes require an explicit backup decision. Overwrite/delete paths back up current remote content before mutation when backup is required.

## Sentinel Rules

Rule types are `flow`, `degrade`, `system`, `authority`, and `param`. Rule storage is schema-over-backend config: Nacos uses `SENTINEL_GROUP` and dataId `{app}-{type}-rules`; Apollo uses item key `{app}-{type}-rules` in rule namespace `SENTINEL` by default; etcd uses key `<keyPrefix><ruleNamespace>/{app}-{type}-rules` with rule namespace `SENTINEL` by default. Kubernetes does not support rules.

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

Service registry commands are Nacos-only. Apollo, etcd, and Kubernetes return NotImplemented.

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
cfgov backup clean (--before <30d|rfc3339|yyyy-mm-dd>|--keep-last <n>) --confirm -o json
cfgov audit query [--since 24h] [--until <rfc3339>] [--type <type>] [--operator <name>] [--context-filter <ctx>] [--status <status>] [--limit 100] -o json
cfgov audit prune (--before <30d|rfc3339|yyyy-mm-dd>|--keep-last <n>) --confirm -o json
cfgov audit verify [--strict] -o json
cfgov version -o json
cfgov install <agent> --skills
```

`backup clean` and `audit prune` default to dry-run; only `--confirm` deletes local files. Do not add `--confirm` unless the human explicitly asked for deletion after reviewing the listed files.

Check `cfgov capabilities -o json` before assuming a backend supports a noun or verb.
