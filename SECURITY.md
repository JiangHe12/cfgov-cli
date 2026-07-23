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
- Kubernetes exec credential plugins are rejected because client-go connects
  plugin stderr directly to the process, outside cfgov's audit-gated diagnostic
  writer. Use static token or client-certificate authentication instead.
- The upstream etcd client parses `ETCD_CLIENT_DEBUG` during package
  initialization. An invalid value can emit one fixed, non-data-bearing warning
  before command audit initialization; leave it unset or use a valid level.
  cfgov suppresses the client's subsequent process-global gRPC logging.
- Prefer keychain or encrypted-file storage; protect contexts, backups, exports,
  and audit evidence with owner-only access.

The trusted local identity is the OS username plus hostname. An AI process and
a human sharing that OS account are not separated by the CLI; stronger approval
requires an external verifier or a separately protected operator identity.

## Supply Chain

Release binaries are built and signed by GitHub Actions. Before GitHub Release
and npm publication, the workflow verifies `checksums.txt` and all six binary
signatures against this repository's exact `release.yml` identity, release ref,
and GitHub Actions OIDC issuer. The npm package embeds those six verified
digests in `package.json`, covered by npm provenance. The installer trusts only
that package-bound manifest; mirrors can supply bytes but cannot replace
verification data. There is no verification bypass, and a failed install leaves
the previous binary unchanged.
