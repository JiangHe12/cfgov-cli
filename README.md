# cfgov-cli

> **Status: early development (P0).** Private, pre-release. The command surface and APIs may change without notice until `v0.1.0`.

Governed CLI for the configuration-governance domain. `cfgov-cli` aims to be the single entry point for config / rule / service-governance middleware (Nacos, Sentinel rules, Apollo, and more), built on the shared [`opskit-core`](https://github.com/JiangHe12/opskit-core) governance engine. It sits alongside `dbgov-cli` (database governance) and `srvgov-cli` (server governance).

P0 ships a Nacos-only governance kernel that proves the spine: a unified backend abstraction, the R0–R3 authorization ladder with protected-context escalation, fail-closed config-write risk classification, audit, and capabilities introspection.

## Architecture

`cfgov-cli` is built on two orthogonal layers:

- **Storage backends** — a namespaced key/value + blob store with revisions and CAS. P0 implements **Nacos**; Apollo / Consul / etcd / Kubernetes are planned. Backend-specific addressing (e.g. Nacos `group/dataId`) is confined to the adapter.
- **Typed schemas** — config blobs today; Sentinel rules and other policy types (gateway routes, feature flags, …) layer on top of any backend in later phases.

A backend is bound to a context (`ctx set --backend nacos`), like `dbgov`'s engine selection; `--backend` overrides per command.

## Governance Model

| Risk | Meaning | Authorization |
|---|---|---|
| R0 | reads and local inspection (still audited) | none |
| R1 | ordinary writes (`config push`) | `--yes` or interactive confirmation |
| R2 | destructive / elevated (`config delete`) | `--ticket` + `--yes` |
| R3 | protected destructive operations | `--ticket` + command-specific `--allow-*` + `--yes` |

Protected contexts raise every operation one tier (`config delete` in a protected context becomes R3 and requires `--allow-production-config-delete`). Impact and blast radius come from the CLI's own `--dry-run` / `--diff`, never from a model guess. **AI agents and automation must never invent `--ticket`, `--allow-*`, or a high-risk `--yes`** — surface missing authorization to the operator.

## Commands (P0)

```
cfgov ctx set <name> --backend nacos --server <url> [--username <u>] [--namespace <ns>] [--protected]
cfgov ctx use|list|current
cfgov config get    --key <dataId|group/dataId>
cfgov config push   --key <key> --file <path> [--type text|properties|json|yaml] [--dry-run]
cfgov config delete --key <key> [--ticket <t> --yes] [--allow-production-config-delete]
cfgov capabilities
cfgov audit query|verify
cfgov version
```

Use `-o json` for automation and AI agents. Credentials are stored via the `opskit-core` credential store; prefer the `NACOS_PASSWORD` env var over `--password`.

## Build & Verify

```bash
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal      # must print nothing
golangci-lint run --timeout=5m
go vet -tags=integration ./...
```

## License

[MIT](LICENSE)
