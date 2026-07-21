# Security Policy

## Supported Versions

Security fixes target the latest release. Upgrade to the newest version when a
security update is published.

## Reporting A Vulnerability

Report vulnerabilities privately through GitHub Security Advisories:

<https://github.com/JiangHe12/cfgov-cli/security/advisories/new>

Do not publish exploit details before a coordinated fix is available. Include
the affected version, platform, backend, impact, reproduction steps, and a
suggested mitigation when possible.

## Trust Boundary

`cfgov-cli` trusts the current OS user, owner-controlled files under `~/.cfgov-cli`,
explicit credential backends, and release artifacts from the canonical GitHub
repository. It does not trust configuration-center responses, imported files,
user-provided URLs, npm mirrors, or model-generated authorization values.

## Governance And Data Handling

- R0 reads and previews are audited. R1 requires confirmation, R2 adds a human
  ticket, and R3 adds the exact operation-specific `--allow-*` flag.
- Context, role, credential, and audit-evidence controls use fixed R3
  authorization and the pre-change policy.
- AI agents must not synthesize tickets, allow flags, or high-risk confirmation.
- Plans are side-effect free and target writes revalidate their bound revision
  where the backend supports compare-and-set.
- Audit and telemetry persist fingerprints and bounded metadata, not raw
  configuration, rule, flag, ticket, reason, credential, or backend error text.
- Prefer keychain or encrypted-file storage; protect contexts, backups, exports,
  and audit evidence with owner-only access.

The trusted local identity is the OS username plus hostname. An AI process and
a human sharing that OS account are not separated by the CLI; stronger approval
requires an external verifier or a separately protected operator identity.

## Supply Chain

Release binaries are built by GitHub Actions, signed, and published with
checksums. Use canonical releases and do not disable installer verification in
production automation.
