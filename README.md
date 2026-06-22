<div align="center">

# cfgov-cli

**Governed configuration, Sentinel-rule & feature-flag operations for humans _and_ AI agents.**

One safe command line for **Nacos**, **Apollo**, **etcd**, and **Kubernetes** — read, diff, change, back up, roll back, and audit your app config, flow-control rules, and feature flags without ever fat-fingering production.

[![npm version](https://img.shields.io/npm/v/cfgov-cli.svg)](https://www.npmjs.com/package/cfgov-cli)
[![CI](https://github.com/JiangHe12/cfgov-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/JiangHe12/cfgov-cli/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/cfgov-cli.svg)](LICENSE)
[![signed](https://img.shields.io/badge/release-cosign%20%2B%20npm%20provenance-blue.svg)](#-trust--verification)

[English](README.md) · [简体中文](README_zh.md)

</div>

---

## 🧭 What is this? (read me first)

Your application's behaviour often lives **outside** your code — in a config center or key-value store like **Nacos**, **Apollo**, **etcd**, or **Kubernetes** ConfigMaps/Secrets: database URLs, feature flags, timeouts, and **Sentinel** flow-control / circuit-breaker rules. Editing those by hand (or letting a script do it) is scary: one wrong `delete` can take down production, and you usually have no preview, no backup, and no record of who changed what.

**cfgov-cli puts guardrails around every one of those operations.** Think of it as a careful assistant that:

- 🔎 **Shows you the blast radius first** — `--dry-run` / `--diff` / `--plan` print exactly what will change before anything happens.
- 🛡️ **Refuses to do something dangerous without explicit sign-off** — risky commands need a confirmation flag, a change ticket, or an explicit "yes, I really mean production".
- 💾 **Backs up before it overwrites or deletes** — and aborts the write if the backup fails.
- 📜 **Records everything in a tamper-evident audit log** — fingerprints only, never your secrets.
- 🤖 **Is safe to hand to an AI agent** — the agent can read and preview freely, but **cannot** invent the human approvals required for dangerous actions.

If you used to run `nacos-cli` or `sentinel-cli`, **cfgov-cli replaces both** — same capabilities, one governed tool, four backends.

---

## ✨ Features

| | |
|---|---|
| 🗄️ **Four backends** | **Nacos** (config, Sentinel rules, feature flags, namespaces, services, history, live-watch), **Apollo** (config + rules + flags), **etcd** (config + rules + flags, native watch), and **Kubernetes** (ConfigMap/Secret config + rules + flags). Pick per context or override per command. |
| ⚙️ **Full config lifecycle** | get · list · diff · validate · pull · history · listen · push · delete · export · import · promote · rollback · reconcile |
| 🚦 **Sentinel rules** | flow · degrade · system · authority · param — read, validate (shallow **and** deep), create, update, import, roll back, delete. Wire-compatible with the Sentinel runtime. |
| 🏁 **Feature flags** | Typed feature-flag sets on **all four backends** — read, validate (shallow **and** deep), create, update, import, roll back, delete. Same schema-over-backend model as rules. |
| 🏷️ **Nacos namespaces & services** | list / create / update / delete namespaces; list / register / deregister service instances. |
| 🔐 **R0–R3 governance** | every operation is risk-classified; protected contexts escalate one tier; AI callers can never self-authorize. |
| 💾 **Backup & rollback** | automatic backup-before-write; restore from a local backup, a backup id, or Nacos history. |
| 📜 **Tamper-evident audit** | hash-chained log of every action (sha256 fingerprints + counts, **no plaintext config**); `audit verify` detects tampering. |
| 🩺 **Ops & DX** | `doctor` diagnostics, shell `completion`, OpenTelemetry traces/metrics, "did you mean…" suggestions, JSON output everywhere. |
| 🔏 **Trusted supply chain** | binaries are **cosign-signed**, the npm package ships with **provenance**, and the installer verifies a **SHA-256** checksum. |

---

## 📦 Install

```bash
npm install -g cfgov-cli
```

This installs a tiny launcher; on first run it downloads the right pre-built binary for your OS/arch from the signed [GitHub Release](https://github.com/JiangHe12/cfgov-cli/releases) and **verifies its SHA-256** before use. Requires Node.js ≥ 14 for the installer (the CLI itself is a self-contained Go binary).

<details>
<summary>Other ways to install</summary>

- **Direct download** — grab the binary for your platform from the [Releases page](https://github.com/JiangHe12/cfgov-cli/releases), verify it against `checksums.txt` (cosign-signed), put it on your `PATH`, and rename it to `cfgov`.
- **From source** — `go install github.com/JiangHe12/cfgov-cli@latest` (Go 1.26+).
- **Mirror / air-gapped** — set `CFGOV_CLI_DOWNLOAD_MIRROR=<base-url>` to fetch the binary from your own mirror.

Verify the install:

```bash
cfgov version
cfgov doctor          # checks context, backend reachability, and audit-log writability
```

</details>

---

## 🚀 Quick start (60 seconds)

```bash
# 1. Point cfgov at your config center (stored as a reusable "context")
cfgov ctx set dev --backend nacos --server http://127.0.0.1:8848 --namespace public
cfgov ctx use dev

# 2. Read something — reads are always free (R0), no flags needed
cfgov config get --key application.yaml -o json
cfgov config list -o json

# 3. Preview a change before doing it — nothing is written yet
cfgov config push --key application.yaml --file ./application.yaml --dry-run --diff

# 4. Apply it — an ordinary write (R1) just needs your confirmation, and is backed up
cfgov config push --key application.yaml --file ./application.yaml --yes --backup

# 5. See what happened
cfgov audit query --since 1h -o json
```

> 💡 **Tip:** mark production contexts with `--protected` when you create them. cfgov then raises the bar for every dangerous operation in that context automatically.

---

## 🔐 The governance model (the important part)

Every command is sorted into one of four **risk tiers**. The higher the tier, the more explicit human sign-off it needs:

| Tier | What it covers | What you must provide |
|:---:|---|---|
| **R0** | Reads & local inspection (`get`, `list`, `diff`, `validate`, `doctor`, …) | Nothing — but it's still audited |
| **R1** | Ordinary writes (`config push`, `rule create/update`, `flag create/update`, `service register`, `namespace create`) | `--yes` (or an interactive confirmation) |
| **R2** | Destructive / elevated (`config delete`, `rule delete`, `flag delete`, `service deregister`, `namespace delete`, `reconcile`) | `--yes` **and** a non-empty `--ticket` |
| **R3** | Protected destructive operations | The above **plus** the exact `--allow-*` flag for that command |

**Protected contexts raise every operation by one tier.** For example, `config delete` is normally R2, but in a `--protected` context it becomes R3 and additionally requires `--allow-production-config-delete`.

Three rules keep this safe — especially for automation:

1. **Blast radius comes from the tool, not a guess.** Use `--dry-run` / `--plan` / `--diff` to see the exact impact. Never estimate it by reasoning.
2. **Destructive writes are backed up first.** Protected contexts require an explicit `--backup` / `--no-backup` decision, and the write aborts if the backup fails.
3. **🤖 AI agents must never invent `--ticket`, `--allow-*`, or a high-risk `--yes`.** Those are *human* authorization inputs. An agent should surface "this needs approval X" to its operator and stop.

---

## 📚 Command reference

`cfgov <noun> <verb> [flags]`. Add `-o json` for machine-readable output, `--help` on any command for its full flag set, and `cfgov capabilities -o json` to ask the bound backend what it actually supports.

<details open>
<summary><b>config</b> — application configuration blobs</summary>

```bash
# Read (R0)
cfgov config get      --key <dataId|group/dataId> -o json
cfgov config list     [--group <g>] [--prefix <p>] [--query <q>] -o json
cfgov config diff     --key <key> --file <path> -o json
cfgov config validate --file <path> [--type text|properties|json|yaml|xml] -o json
cfgov config pull     --key <key> --file <path>
cfgov config history  --key <key> -o json
cfgov config listen   --key <key> [--max-events 1] [--long-poll 30s] -o json
cfgov config export   --dir <dir> [--group <g>] [--prefix <p>] -o json

# Write
cfgov config push     --key <key> --file <path> [--dry-run --diff] --yes --backup        # R1
cfgov config delete   --key <key> --yes --ticket <t> [--allow-production-config-delete]  # R2 / R3
cfgov config import    --dir <dir> --dry-run --plan                                       # R1
cfgov config promote   --source-context <ctx> (--key <k>|--prefix <p>) --dry-run --diff   # R1
cfgov config rollback  --key <key> (--backup-file <f>|--backup-id <id>|--history-id <id>) # R1
cfgov config reconcile --dir <dir> [--prune --prune-scope <s> --allow-production-prune]   # R2 / R3
```
</details>

<details>
<summary><b>rule</b> — Sentinel flow-control rules (flow · degrade · system · authority · param)</summary>

```bash
# Read & validate (R0)
cfgov rule list     --app <app> [--type <type>] -o json
cfgov rule get      --app <app> --type <type> [--resource <name>] -o json
cfgov rule export   --app <app> --dir <dir> -o json
cfgov rule diff     --app <app> --type <type> --file <path> -o json
cfgov rule diff     --app <app> --dir <dir> -o json
cfgov rule validate --file <path> [--deep] [--fail-on-warnings] -o json
cfgov rule validate --dir <dir> --deep [--fail-on-warnings] -o json

# Write
cfgov rule create   --app <app> --type <type> --file <path> [--dry-run --diff] --yes      # R1
cfgov rule update   --app <app> --type <type> --file <path> --yes                         # R1
cfgov rule import   --app <app> --from-dir <dir> --dry-run --plan --yes                   # R1
cfgov rule rollback --app <app> --backup <ref> --yes                                      # R1
cfgov rule delete   --app <app> --type <type> --yes --ticket <t> [--allow-production-rule-delete]  # R2 / R3
```

Every rule write passes shallow JSON/schema validation; create/update/import/rollback also run **deep** semantic checks that flags cannot bypass. `rule validate --file --deep` runs checks that are meaningful for one isolated rule type; use `rule validate --dir --deep` for cross-rule checks such as `param` without matching `flow` or `flow`/`degrade` grade mismatch. Rule sets are stored as config blobs (Nacos group `SENTINEL_GROUP`, dataId `{app}-{type}-rules`; Apollo namespace `SENTINEL`, item `{app}-{type}-rules`; etcd key `<keyPrefix>SENTINEL/{app}-{type}-rules`; Kubernetes ConfigMap `{app}-{type}-rules`, data key `rules.json`) so they stay wire-compatible with the Sentinel runtime. The Kubernetes layout is a ConfigMap / file-datasource convention, not a CRD datasource.
</details>

<details>
<summary><b>flag</b> — feature flags (cfgov-native typed policy, all four backends)</summary>

```bash
# Read & validate (R0)
cfgov flag list     --app <app> -o json
cfgov flag get      --app <app> [--key <key>] -o json
cfgov flag export   --app <app> --dir <dir> -o json
cfgov flag diff     --app <app> (--file <path>|--dir <dir>) -o json
cfgov flag validate (--file <path>|--dir <dir>) [--deep] [--fail-on-warnings] -o json

# Write
cfgov flag create   --app <app> --file <path> [--force] [--dry-run --diff] --yes      # R1
cfgov flag update   --app <app> --file <path> --yes                                   # R1
cfgov flag import   --app <app> (--file <path>|--dir <dir>) --dry-run --plan --yes     # R1
cfgov flag rollback --app <app> --backup <ref> --yes                                  # R1
cfgov flag delete   --app <app> (--key <key>|--all) --yes --ticket <t> [--allow-production-flag-delete]  # R2 / R3
```

A feature flag set is one JSON array of typed flags (`key`, `enabled`, `defaultVariant`, `variants`, percentage-rollout `rules`) stored as a single config blob per app: key `{app}-flags` (Nacos group `FEATURE_FLAG_GROUP`; Apollo/etcd under the bound namespace; Kubernetes ConfigMap `{app}-flags`, data key `flags.json`). create/update/import/rollback run **deep** semantic checks that flags cannot bypass — duplicate key, `rolloutPercent` out of 0–100, and variant integrity (`defaultVariant` / each rule `variant` must exist). `delete` needs either a specific `--key` or `--all`. Feature flags are cfgov-native (no external runtime convention), so they simply reuse each backend's bound namespace.
</details>

<details>
<summary><b>namespace</b> & <b>service</b> — Nacos only (Apollo, etcd & Kubernetes fail closed with NotImplemented)</summary>

```bash
cfgov namespace list   -o json                                                           # R0
cfgov namespace create --id <id> --name <name> [--desc <d>] --dry-run --plan --yes        # R1
cfgov namespace delete --id <id> --yes --ticket <t> [--allow-production-namespace-delete] # R2 / R3 (+ y/N confirm)

cfgov service list      -o json                                                           # R0
cfgov service get       --service <name> -o json                                          # R0
cfgov service instances --service <name> -o json                                          # R0
cfgov service register  --service <name> --ip <ip> --port <port> [--ephemeral|--persistent] --yes   # R1
cfgov service deregister --service <name> --ip <ip> --port <port> --yes --ticket <t> \
                         [--allow-production-service-deregister]                          # R2 / R3
```
</details>

<details>
<summary><b>backup</b>, <b>audit</b>, <b>ctx</b>, <b>doctor</b> & friends</summary>

```bash
# Local backup store
cfgov backup list  [--context-filter <c>] [--namespace <n>] [--data-id <k>] -o json
cfgov backup clean (--before <30d|RFC3339|YYYY-MM-DD> | --keep-last <n>) [--confirm]   # dry-run unless --confirm

# Audit (tamper-evident)
cfgov audit query  [--since 24h] [--type <t>] [--operator <o>] [--status <s>] [--limit 100] -o json
cfgov audit verify [--strict] -o json
cfgov audit prune  (--before <…> | --keep-last <n>) [--confirm]                       # dry-run unless --confirm

# Contexts
cfgov ctx set <name> --backend nacos  --server <url> [--namespace <ns>] [--protected]
cfgov ctx set <name> --backend apollo --server <url> --apollo-app-id <id> --apollo-env <env> \
                     --apollo-cluster <c> --apollo-namespace <ns>
cfgov ctx set <name> --backend etcd   --server <host:port,host:port> [--etcd-key-prefix <p>] \
                     [--etcd-rule-namespace SENTINEL] [--namespace <ns>] \
                     [--etcd-ca-cert <f>] [--etcd-client-cert <f>] [--etcd-client-key <f>]
cfgov ctx set <name> --backend k8s    [--k8s-kubeconfig <path>] [--k8s-context <c>] --namespace <k8s-ns>
cfgov ctx use|list|current|delete|export|import|test
cfgov ctx role set|unset|list <context>

# Diagnostics & ecosystem
cfgov doctor -o json            # read-only health check (redacted output)
cfgov capabilities -o json      # what the bound backend supports
cfgov completion bash|zsh|fish|powershell
cfgov install <agent> --skills  # install the cfgov AI skill into an agent (claude, codex, …)
cfgov version
```

> `backup clean` and `audit prune` **only delete local files**, default to a **dry-run**, and require `--confirm` to actually remove anything. The deletion itself is audited.
</details>

---

## 🤖 For AI agents

cfgov-cli is designed to be driven by autonomous agents safely:

- Run `cfgov capabilities -o json` first to discover supported nouns/verbs and their risk tiers — don't assume.
- Use `-o json` everywhere; every command returns a stable, versioned envelope.
- Get blast radius from `--dry-run` / `--plan` / `--diff`, never from your own reasoning.
- **Never self-fill `--ticket`, `--allow-*`, or a high-risk `--yes`.** Surface the required human approval and stop.

Install the bundled skill into your agent so it learns these rules automatically:

```bash
cfgov install claude --skills     # also: codex, opencode, copilot, cursor, windsurf, aider, cc-switch
```

---

## 🔏 Trust & verification

- **Signed binaries** — every release artifact is signed with [cosign](https://github.com/sigstore/cosign) (keyless / OIDC). A `checksums.txt` (also signed) covers all platforms.
- **npm provenance** — the npm package is published from CI via OpenID Connect with [provenance attestations](https://docs.npmjs.com/generating-provenance-statements) linking it to this exact repo and workflow.
- **Verified installs** — the npm postinstall downloads the binary over an allow-listed host and checks its SHA-256 against the signed `checksums.txt` before installing.
- **Tamper-evident audit** — `cfgov audit verify --strict` re-walks the hash chain and reports any gap or modification.

---

## 🏗️ Build from source & contribute

```bash
git clone https://github.com/JiangHe12/cfgov-cli && cd cfgov-cli
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal      # must print nothing
golangci-lint run --timeout=5m
go vet -tags=integration ./...
```

cfgov-cli is built on the shared [`opskit-core`](https://github.com/JiangHe12/opskit-core) governance engine and is part of the **opskit** family of governed CLIs for AI agents — alongside [`dbgov-cli`](https://www.npmjs.com/package/dbgov-cli) (databases) and `srvgov-cli` (remote servers).

---

## 📄 License

[MIT](LICENSE) © JiangHe12
