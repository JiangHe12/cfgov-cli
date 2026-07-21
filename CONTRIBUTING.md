# Contributing

Thank you for contributing. `cfgov-cli` is security-sensitive infrastructure
software, so changes should stay focused, tested, and straightforward to
review.

## Development

Run every gate before submitting changes:

```bash
go build ./...
go test -count=1 ./...
gofmt -l main.go cmd internal   # must print nothing
golangci-lint run --timeout=5m
go vet -tags=integration ./...
npm pack --dry-run
```

Do not commit credentials, context files, audit logs, backups, exported
configuration, or downloaded release binaries.

## Pull Requests

- Keep one behavioral topic per pull request.
- Add adversarial tests for authorization, validation, redaction, plan/apply
  binding, and backend capability boundaries.
- Update both READMEs and the embedded Skill when user-facing behavior changes.
- Never weaken governance or production authorization to make a test pass.

## Releases

Maintainers release from `main` with `v*` tags. Do not create tags or publish
packages unless explicitly authorized.
