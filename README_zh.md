<div align="center">

# cfgov-cli

**面向人类与 AI 智能体的「带治理」配置、Sentinel 规则 & 特性开关操作命令行。**

一个安全的命令行,统一管理 **Nacos**、**Apollo**、**etcd**、**Kubernetes** 与 **Consul** 上的应用配置、流控规则与特性开关——读取、对比、修改、备份、回滚、审计,再也不会手滑改挂生产。

[![npm version](https://img.shields.io/npm/v/cfgov-cli.svg)](https://www.npmjs.com/package/cfgov-cli)
[![CI](https://github.com/JiangHe12/cfgov-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/JiangHe12/cfgov-cli/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/cfgov-cli.svg)](LICENSE)
[![signed](https://img.shields.io/badge/release-cosign%20%2B%20npm%20provenance-blue.svg)](#-供应链可信与校验)

[English](README.md) · [简体中文](README_zh.md)

</div>

---

## 🧭 这是什么?(先看这里)

应用的行为往往不只在代码里,还活在 **Nacos / Apollo / etcd / Kubernetes**(ConfigMap/Secret)**/ Consul** 这类配置中心或键值存储中:数据库地址、功能开关、超时时间,以及 **Sentinel** 的流控 / 熔断规则。手动改(或让脚本去改)这些东西很可怕:一条 `delete` 写错就能搞挂生产,而且通常没有预览、没有备份、也没人知道是谁改了什么。

**cfgov-cli 给每一个这样的操作都套上了护栏。** 把它想成一个谨慎的助手:

- 🔎 **先告诉你影响范围**——`--dry-run` / `--diff` / `--plan` 在任何改动发生前,精确打印将要变更的内容。
- 🛡️ **没有明确授权,绝不执行危险操作**——高风险命令需要确认标志、变更工单,或一句明确的「是的,我就是要动生产」。
- 💾 **覆盖或删除前先备份**——备份失败则中止写入。
- 📜 **所有操作记入防篡改审计日志**——只记指纹,绝不记你的明文密钥。
- 🤖 **可以放心交给 AI 智能体**——智能体能自由读取、预览,但**无法**伪造危险操作所需的人类审批。

如果你以前用 `nacos-cli` 或 `sentinel-cli`,**cfgov-cli 同时取代了这两者**——能力一致,一个带治理的工具,五后端。

---

## ✨ 功能一览

| | |
|---|---|
| 🗄️ **五后端** | **Nacos**(配置、Sentinel 规则、特性开关、命名空间、服务、历史、实时监听)、**Apollo**(配置 + 规则 + 开关)、**etcd**(配置 + 规则 + 开关、原生 watch)、**Kubernetes**(ConfigMap/Secret 配置 + 规则 + 开关、对象级 watch)与 **Consul**(配置 + 规则 + 开关 + 服务、阻塞查询 watch)。可按上下文绑定,也可按命令临时覆盖。 |
| ⚙️ **完整配置生命周期** | get · list · diff · validate · pull · history · listen · push · delete · export · import · promote · rollback · reconcile |
| 🚦 **Sentinel 规则** | flow · degrade · system · authority · param——读取、校验(浅 **+** 深)、创建、更新、导入、回滚、删除。与 Sentinel 运行时**线格式兼容**。 |
| 🏁 **特性开关** | 类型化的特性开关集,**五后端通吃**——读取、校验(浅 **+** 深)、创建、更新、导入、回滚、删除。与规则同样的 schema-over-backend 模型。 |
| 🏷️ **命名空间 & 服务** | 命名空间(Nacos):list / create / update / delete。服务(**Nacos + Consul**):list / get / instances / register / deregister。 |
| 🔐 **R0–R3 治理** | 每个操作都做风险分级;受保护上下文整体升一档;AI 调用者永远无法自我授权。 |
| 💾 **备份与回滚** | 写前自动备份;可从本地备份、备份 id 或 Nacos 历史恢复。 |
| 📜 **防篡改审计** | 哈希链记录每次操作(sha256 指纹 + 计数,**不含明文配置**);`audit verify` 可检测篡改。 |
| 🩺 **运维与体验** | `doctor` 诊断、shell `completion` 补全、OpenTelemetry 链路/指标、输错命令的「您是不是想…」提示、处处可 JSON 输出。 |
| 🔏 **可信供应链** | 二进制经 **cosign 签名**,npm 包带 **provenance 溯源**,安装器校验 **SHA-256**。 |

---

## 📦 安装

```bash
npm install -g cfgov-cli
```

这会装一个很小的启动器;首次运行时,它会从已签名的 [GitHub Release](https://github.com/JiangHe12/cfgov-cli/releases) 下载对应你 OS/架构的预编译二进制,并在使用前**校验 SHA-256**。安装器需要 Node.js ≥ 14(CLI 本身是自包含的 Go 二进制)。

<details>
<summary>其它安装方式</summary>

- **直接下载**——从 [Releases 页面](https://github.com/JiangHe12/cfgov-cli/releases)取对应平台二进制,用(cosign 签名的)`checksums.txt` 校验,放进 `PATH` 并重命名为 `cfgov`。
- **从源码**——`go install github.com/JiangHe12/cfgov-cli@latest`(Go 1.26+)。
- **镜像 / 内网隔离**——设置 `CFGOV_DOWNLOAD_MIRROR=<base-url>`,从你自己的镜像拉二进制。旧的 `CFGOV_CLI_DOWNLOAD_MIRROR` 仍兼容但已 deprecated。

验证安装:

```bash
cfgov version
cfgov doctor          # 检查上下文、后端可达性、审计日志可写性
```

</details>

---

## 🚀 快速上手(60 秒)

```bash
# 1. 先预览，再用人工授权应用固定 R3 的 context 变更
cfgov ctx set dev --backend nacos --server http://127.0.0.1:8848 --namespace public --plan -o json
cfgov ctx set dev --backend nacos --server http://127.0.0.1:8848 --namespace public --yes --ticket <human-ticket> --allow-context-change
cfgov ctx use dev --plan -o json
cfgov ctx use dev --yes --ticket <human-ticket> --allow-context-change
# 认证 Nacos 时加 --username <user>,运行命令时设置 CFGOV_PASSWORD。

# 2. 读点东西——读操作永远免费(R0),无需任何标志
cfgov config get --key application.yaml -o json
cfgov config list -o json

# 3. 改动前先预览——此时什么都还没写入
cfgov config push --key application.yaml --file ./application.yaml --dry-run --diff

# 4. 真正应用——普通写入(R1)只需你确认,且会自动备份
cfgov config push --key application.yaml --file ./application.yaml --yes --backup

# 5. 看看刚才发生了什么
cfgov audit query --since 1h -o json
```

> 💡 **提示:** 创建生产上下文时加上 `--protected`。之后 cfgov 会自动为该上下文里的每个危险操作提高门槛。

---

## 🔐 治理模型(最重要的部分)

每条命令都会被归入四个**风险档位**之一。档位越高,需要的人类授权越明确:

| 档位 | 涵盖范围 | 你必须提供 |
|:---:|---|---|
| **R0** | 读取与本地查看(`get`、`list`、`diff`、`validate`、`doctor` …) | 无——但仍会被审计 |
| **R1** | 普通写入(`config push`、`rule create/update`、`flag create/update`、`service register`、`namespace create`) | `--yes`(或交互式确认) |
| **R2** | 破坏性 / 升级操作(`config delete`、`rule delete`、`flag delete`、`service deregister`、`namespace delete`、`reconcile`) | `--yes` **加** 非空的 `--ticket` |
| **R3** | 治理控制变更与受保护的破坏性操作 | 以上**再加**该命令专属的 `--allow-*` 标志 |

**受保护上下文会把每个操作整体升一档。** 例如 `config delete` 通常是 R2,但在 `--protected` 上下文里会变成 R3,并额外要求 `--allow-production-config-delete`。不带 prune 的 `config reconcile` 在受保护上下文中同样需要 `--allow-production-reconcile`;prune 操作始终使用范围更精确的 `--allow-production-prune`。

三条原则保证它的安全——尤其是对自动化:

1. **影响范围来自工具,而非猜测。** 用 `--dry-run` / `--plan` / `--diff` 看精确影响,绝不靠推理估算。
2. **破坏性写入先备份。** 受保护上下文要求显式的 `--backup` / `--no-backup` 决定,备份失败则中止写入。
3. **🤖 AI 智能体绝不能伪造 `--ticket`、`--allow-*` 或高风险 `--yes`。** 它们是*人类*授权输入。智能体应当把「这步需要审批 X」上报给操作者并停下。

cfgov 使用本机 OS 用户名加 hostname 生成授权与审计操作者身份。旧的根级 `--operator` 以及 `CFGOV_OPERATOR` / `CFGOV_CLI_OPERATOR` 环境变量仅作为已弃用兼容输入保留，身份与授权会忽略它们；`audit query --operator` 仍只用于筛选审计记录。这能阻止通过标志或环境变量伪造身份，但**不能**区分同一 OS 账户下运行的 AI 进程与人类。要建立这层边界，仍需外部可验证的审批机制或独立 OS 身份。

`--plan` 是后端写入和本地目标变更的强制零副作用开关,覆盖上下文 / RBAC / 凭据、pull / export、审计 repair / prune、备份清理和 Skill 安装。它的优先级高于 `--confirm`;命令自己的 `--dry-run` 标志仍然有效,写命令用 `--diff` 返回 `ChangePlan` 时也属于预览。每次成功完成的预览只写一条 `command.preview` 审计,其 `status=skipped`,并显式带有 `preview=true` / `dryRun=true`;若该记录无法追加,命令会失败。受治理的审计日志(包括真实发生读取时的资源读取审计)是预览唯一允许修改的本地目标。

`config export`、`rule export` 和 `flag export` 只允许新建文件。命令会在 mutation intent 前检查所有生成名称和目标路径;名称碰撞或目标文件已存在时,plan 与实际执行都会失败,实际落盘还使用排他创建,因此导出绝不会覆盖已有文件。

每个真实的后端、凭据、上下文、RBAC 或本地文件变更，都会在授权与最终校验之后、第一次目标写入之前同步写入一条 `MutationAuditRecord` intent，并在返回普通成功之前写入 outcome。批量命令只使用一组 intent / outcome，并汇总 `succeeded` / `failed` / `skipped` 计数。core v2 的提交状态是权威依据：只有明确未提交的 outcome 才会原子写入并 fsync 到仅所有者可访问的 `<audit.log>.outcome-spool`；已提交但收尾失败或提交状态不确定的 outcome 不会被盲目排队。明确未提交的条目仍按至少一次语义重放；若重放结果不确定，该条目会改名为 `.indeterminate` 并阻断后续自动重放，直至按 `mutationId + phase` 人工核对。所有不完整路径均返回 `AUDIT_INCOMPLETE`；intent 写入失败时目标保持不变。

新的审计与遥测记录不包含明文 ticket、reason、配置 / 规则 / 特性开关正文或完整错误文本，只保留域隔离 SHA-256 指纹、字节 / 条目计数、revision 与机器错误码。`audit query` 输出历史记录时也会移除旧的明文 ticket / reason / diff / error message。

---

## 📚 命令参考

`cfgov <名词> <动词> [标志]`。加 `-o json` 得到机器可读输出,任意命令加 `--help` 看完整标志,`cfgov capabilities -o json` 可询问当前后端实际支持什么。

<details open>
<summary><b>config</b> — 应用配置 blob</summary>

```bash
# 读取(R0)
cfgov config get      --key <dataId|group/dataId> -o json
cfgov config list     [--group <g>] [--prefix <p>] [--query <q>] -o json
cfgov config diff     --key <key> --file <path> -o json
cfgov config validate --file <path> [--type text|properties|json|yaml|xml] -o json
cfgov config pull     --key <key> --file <path>
cfgov config history  --key <key> -o json
cfgov config listen   --key <key> [--max-events 1] [--long-poll 30s] -o json
cfgov config export   --dir <dir> [--group <g>] [--prefix <p>] -o json

# 写入
cfgov config push     --key <key> --file <path> [--dry-run --diff] --yes --backup        # R1
cfgov config delete   --key <key> --yes --ticket <t> [--allow-production-config-delete]  # R2 / R3
cfgov config import    --dir <dir> --dry-run --plan                                       # R1
cfgov config promote   --source-context <ctx> (--key <k>|--prefix <p>) --dry-run --diff   # R1
cfgov config rollback  --key <key> (--backup-file <f>|--backup-id <id>|--history-id <id>) # R1
cfgov config reconcile --dir <dir> [--allow-production-reconcile] [--prune --prune-scope <s> --allow-production-prune] # R2 / R3
```

外部取消的 `config listen` 会以非零状态退出；自动化不得把取消误判为成功完成。
</details>

<details>
<summary><b>rule</b> — Sentinel 流控规则(flow · degrade · system · authority · param)</summary>

```bash
# 读取与校验(R0)
cfgov rule list     --app <app> [--type <type>] -o json
cfgov rule get      --app <app> --type <type> [--resource <name>] -o json
cfgov rule export   --app <app> --dir <dir> -o json
cfgov rule diff     --app <app> --type <type> --file <path> -o json
cfgov rule diff     --app <app> --dir <dir> -o json
cfgov rule validate --file <path> [--deep] [--fail-on-warnings] -o json
cfgov rule validate --dir <dir> --deep [--fail-on-warnings] -o json

# 写入
cfgov rule create   --app <app> --type <type> --file <path> [--dry-run --diff] --yes      # R1
cfgov rule update   --app <app> --type <type> --file <path> --yes                         # R1
cfgov rule import   --app <app> --from-dir <dir> --dry-run --plan --yes                   # R1
cfgov rule rollback --app <app> --backup <ref> --yes                                      # R1
cfgov rule delete   --app <app> --type <type> --yes --ticket <t> [--allow-production-rule-delete]  # R2 / R3
```

每个规则写入都会先过浅层 JSON/schema 校验;create/update/import/rollback 还会跑**深层**语义检查,且标志无法绕过。`rule validate --file --deep` 只跑对单个孤立规则类型有意义的检查;跨类型检查(如 param 没有对应 flow、flow/degrade grade 不一致)请用 `rule validate --dir --deep`。规则集以配置 blob 形式存储(Nacos group `SENTINEL_GROUP`、dataId `{app}-{type}-rules`;Apollo namespace `SENTINEL`、item `{app}-{type}-rules`;etcd key `<keyPrefix>SENTINEL/{app}-{type}-rules`;Consul key `<keyPrefix>SENTINEL/{app}-{type}-rules`;Kubernetes ConfigMap `{app}-{type}-rules`、数据键 `rules.json`),从而与 Sentinel 运行时保持线格式兼容。其中 Kubernetes 采用的是 ConfigMap / file-datasource 约定,而非基于 CRD 的 datasource。
</details>

<details>
<summary><b>flag</b> — 特性开关(cfgov 原生类型化策略,五后端通吃)</summary>

```bash
# 读取与校验(R0)
cfgov flag list     --app <app> -o json
cfgov flag get      --app <app> [--key <key>] -o json
cfgov flag export   --app <app> --dir <dir> -o json
cfgov flag diff     --app <app> (--file <path>|--dir <dir>) -o json
cfgov flag validate (--file <path>|--dir <dir>) [--deep] [--fail-on-warnings] -o json

# 写入
cfgov flag create   --app <app> --file <path> [--force] [--dry-run --diff] --yes      # R1
cfgov flag update   --app <app> --file <path> --yes                                   # R1
cfgov flag import   --app <app> (--file <path>|--dir <dir>) --dry-run --plan --yes     # R1
cfgov flag rollback --app <app> --backup <ref> --yes                                  # R1
cfgov flag delete   --app <app> (--key <key>|--all) --yes --ticket <t> [--allow-production-flag-delete]  # R2 / R3
```

一个特性开关集就是一组类型化开关的 JSON 数组(`key`、`enabled`、`defaultVariant`、`variants`、按百分比灰度的 `rules`),以单个配置 blob 形式按 app 存储:key 为 `{app}-flags`(Nacos group `FEATURE_FLAG_GROUP`;Apollo/etcd/Consul 落在绑定的命名空间下;Kubernetes ConfigMap `{app}-flags`、数据键 `flags.json`)。create/update/import/rollback 会跑**深层**语义检查且无法被标志绕过——重复 key、`rolloutPercent` 越界 0–100、variant 完整性(`defaultVariant` 与每条规则的 `variant` 必须存在)。`delete` 需指定具体 `--key` 或 `--all`。特性开关是 cfgov 原生策略(无外部运行时约定),因此直接复用各后端绑定的命名空间。
</details>

<details>
<summary><b>namespace</b>(仅 Nacos)与 <b>service</b>(Nacos + Consul)</summary>

```bash
cfgov namespace list   -o json                                                           # R0
cfgov namespace create --id <id> --name <name> [--desc <d>] --dry-run --plan --yes        # R1
cfgov namespace delete --id <id> --yes --ticket <t> [--allow-production-namespace-delete] # R2 / R3(+ y/N 二次确认)

cfgov service list      -o json                                                           # R0
cfgov service get       --service <name> -o json                                          # R0
cfgov service instances --service <name> -o json                                          # R0
cfgov service register  --service <name> --ip <ip> --port <port> [--ephemeral|--persistent] --yes   # R1
cfgov service deregister --service <name> --ip <ip> --port <port> --yes --ticket <t> \
                         [--allow-production-service-deregister]                          # R2 / R3
```

`namespace` 仅 Nacos;`service` 支持 **Nacos 与 Consul**,Apollo、etcd、Kubernetes 均 fail-closed 返回 NotImplemented。Consul 实例为 agent 注册、用确定性 id `{service}-{ip}-{port}`,健康状态来自真实 Consul checks;Nacos 专属的 `--ephemeral`/`group`/`cluster` 会保留为 Consul 服务 metadata,而非伪造。
</details>

<details>
<summary><b>backup</b>、<b>audit</b>、<b>ctx</b>、<b>doctor</b> 等</summary>

```bash
# 本地备份库
cfgov backup list  [--context-filter <c>] [--namespace <n>] [--data-id <k>] -o json
cfgov backup clean (--before <30d|RFC3339|YYYY-MM-DD> | --keep-last <n>) [--confirm]   # 不加 --confirm 即 dry-run

# 审计(防篡改)
cfgov audit query  [--since 24h] [--type <t>] [--operator <o>] [--status <s>] [--limit 100] -o json
cfgov audit verify [--strict] -o json
cfgov audit verify --repair --confirm --yes --ticket <t> --allow-audit-repair -o json # R3
cfgov audit prune  (--before <…> | --keep-last <n>)                                  # dry-run
cfgov audit prune  (--before <…> | --keep-last <n>) --confirm --yes --ticket <t> --allow-audit-prune -o json # R3

# 上下文
cfgov ctx set <name> --backend nacos  --server <url> [--namespace <ns>] [--username <u>] [--protected]
cfgov ctx set <name> --backend apollo --server <url> --apollo-app-id <id> --apollo-env <env> \
                     --apollo-cluster <c> --apollo-namespace <ns>
cfgov ctx set <name> --backend etcd   --server <host:port,host:port> [--etcd-key-prefix <p>] \
                     [--etcd-rule-namespace SENTINEL] [--namespace <ns>] \
                     [--etcd-ca-cert <f>] [--etcd-client-cert <f>] [--etcd-client-key <f>]
cfgov ctx set <name> --backend k8s    [--k8s-kubeconfig <path>] [--k8s-context <c>] --namespace <k8s-ns>
cfgov ctx set <name> --backend consul --server <host:port> [--consul-key-prefix <p>] \
                     [--consul-rule-namespace SENTINEL] [--namespace <ns>] \
                     [--consul-ca-cert <f>] [--consul-client-cert <f>] [--consul-client-key <f>]
cfgov ctx use|list|current|delete|export|import|migrate-credentials|test
cfgov ctx role set|unset|list <context>
#   context 创建/替换/切换/import/凭据迁移均为 R3:
#     --yes --ticket <人工工单> --allow-context-change
#   context 删除为 R3: --yes --ticket <人工工单> --allow-context-delete
#   role set/unset 为 R3: --yes --ticket <人工工单> --allow-role-change
#   已有 set/import 目标使用自身的变更前策略;新目标使用持久化 current context 的策略,
#   不存在 current 时使用空 bootstrap 策略。ctx use 优先使用旧 current 策略,没有旧 current
#   时才使用目标策略。--plan 在授权前返回预览,且不写目标。
#   apply 路径会在 context 文件锁内重读并授权该策略;凭据迁移会先授权锁内完整批次,
#   再执行首个凭据写入。portable import 只接受单个且字段已知的 YAML 文档,并在不写凭据的前提下
#   校验凭据后端可用性、ticketPattern 语法及内联 reader/writer/admin 角色。
#   Nacos 密码:context 未保存凭据时,非交互运行优先用 CFGOV_PASSWORD。
#   若要持久化密码,用 ctx set --password <pw> 配 --credential-backend keychain|encrypted-file。
#   ctx set --plan 仍会加载并校验上下文配置及凭据后端可用性,但不会写入两者。
#   若要迁移已有明文凭据,先用 ctx migrate-credentials --dry-run 预览,再提供上述 R3 标志。
#   --server URL 内联 userinfo 仍兼容;显式 --password/CFGOV_PASSWORD 优先。
#   Vault 凭据后端要求 --vault-addr 为绝对 HTTPS URL，且不能包含 userinfo、query 或 fragment。

# 诊断与生态
cfgov doctor -o json            # 只读健康检查(输出已脱敏)
# cfgov doctor --plan 将审计写检查标为 skipped 且 complete=false,不会声称已验证可写性。
cfgov capabilities -o json      # 当前后端支持什么
cfgov completion bash|zsh|fish|powershell
cfgov install <agent> --skills  # 把 cfgov AI 技能装进某个智能体(claude、codex …)
cfgov version
```

> `backup clean` 和 `audit prune` **只删本地文件**,并默认 **dry-run**。确认执行的审计 prune 与 repair 是固定 R3 的证据变更:必须同时提供 `--confirm`、`--yes`、非空 `--ticket` 及精确的 `--allow-audit-prune` / `--allow-audit-repair`。授权使用持久化 current context 策略(没有 current 时为空策略),`--context` 不能替换该策略。预览会在授权前返回,不删除或重写审计证据。core v2 会持有审计路径锁、把确认绑定到精确预览集合、完整验证历史，并在集合变化时返回 `CONFLICT`。prune 支持认证 v2 历史，并在删除前持久推进 checkpoint；repair 仍只支持 legacy 历史。两种操作的 mutation intent/outcome 都写入同目录 sibling `.<audit-base>-control`，避免转换目标日志或让 control rotation 污染目标日志命名空间。
</details>

---

## 🤖 给 AI 智能体

cfgov-cli 在设计上就能被自主智能体安全驱动:

- 先跑 `cfgov capabilities -o json` 发现支持的名词/动词及其风险档位——不要假设。
- 处处用 `-o json`;每条命令都返回稳定、带版本的信封结构。
- 影响范围取自 `--dry-run` / `--plan` / `--diff`,绝不靠自己推理。
- **绝不自我填入 `--ticket`、`--allow-*` 或高风险 `--yes`。** 把所需的人类审批上报,然后停下。

把内置技能装进你的智能体,让它自动学会这些规则:

```bash
cfgov install claude --skills     # 也支持:codex、opencode、copilot、cursor、windsurf、aider、cc-switch
```

---

## 🔏 供应链可信与校验

- **签名二进制**——每个发布产物都用 [cosign](https://github.com/sigstore/cosign) 无密钥(OIDC)签名;`checksums.txt` 覆盖全平台并同样签名。
- **npm provenance**——npm 包由 CI 经 OpenID Connect 发布,带 [provenance 溯源声明](https://docs.npmjs.com/generating-provenance-statements),将其与本仓库及工作流精确关联。
- **校验式安装**——npm postinstall 通过白名单主机下载二进制,并在安装前对照已签名的 `checksums.txt` 校验 SHA-256。
- **防篡改审计**——`cfgov audit verify --strict` 会重走哈希链,报告任何断裂或改动。

---

## 🏗️ 从源码构建与贡献

```bash
git clone https://github.com/JiangHe12/cfgov-cli && cd cfgov-cli
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal      # 必须无输出
golangci-lint run --timeout=5m
go vet -tags=integration ./...
```

完整验证流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，漏洞报告方式与安全边界见
[SECURITY.md](SECURITY.md)。

cfgov-cli 构建于共享治理引擎 [`opskit-core`](https://github.com/JiangHe12/opskit-core) 之上,是面向 AI 智能体的 **opskit** 治理型 CLI 家族的一员——同族还有 [`dbgov-cli`](https://www.npmjs.com/package/dbgov-cli)(数据库)、[`srvgov-cli`](https://www.npmjs.com/package/srvgov-cli)(远程服务器)与 [`mqgov-cli`](https://www.npmjs.com/package/mqgov-cli)(消息中间件)。

---

## 📄 许可证

[MIT](LICENSE) © JiangHe12
