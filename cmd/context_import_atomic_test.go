package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/safety"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type atomicImportCredentialBackend struct {
	name          string
	values        map[string]string
	gets          int
	puts          int
	deletes       int
	putError      func(int) error
	putAfterError func(int) error
	deleteErr     error
	beforeDelete  func(int)
}

func (b *atomicImportCredentialBackend) Name() string {
	if b.name != "" {
		return b.name
	}
	return credentialBackendEncrypted
}

func (b *atomicImportCredentialBackend) Get(ctx context.Context, name string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b.gets++
	value, ok := b.values[name]
	if !ok {
		return "", credstore.ErrNotFound
	}
	return value, nil
}

func (b *atomicImportCredentialBackend) Put(ctx context.Context, name, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.puts++
	if b.putError != nil {
		if err := b.putError(b.puts); err != nil {
			return err
		}
	}
	b.values[name] = password
	if b.putAfterError != nil {
		if err := b.putAfterError(b.puts); err != nil {
			return err
		}
	}
	return nil
}

func (b *atomicImportCredentialBackend) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.deletes++
	if b.beforeDelete != nil {
		b.beforeDelete(b.deletes)
	}
	if b.deleteErr != nil {
		return b.deleteErr
	}
	delete(b.values, name)
	return nil
}

func (b *atomicImportCredentialBackend) Available() error { return nil }

func TestContextImportValidationAndLockedConflictWriteNoCredential(t *testing.T) {
	tests := []struct {
		name        string
		context     cfgovctx.Context
		locked      *corectx.Config[cfgovctx.Context]
		wantCode    apperrors.ErrorCode
		wantGets    int
		wantIntents int
	}{
		{
			name: "portable validation failure",
			context: cfgovctx.Context{
				Base:    corectx.Base{Server: "not-an-absolute-url", Password: "new-secret", CredentialBackend: credentialBackendEncrypted},
				Backend: "nacos",
			},
			wantCode: apperrors.CodeUsageError,
		},
		{
			name: "locked target conflict",
			context: cfgovctx.Context{
				Base:    corectx.Base{Server: "http://127.0.0.1:8848", Password: "new-secret", CredentialBackend: credentialBackendEncrypted},
				Backend: "nacos",
			},
			locked: &corectx.Config[cfgovctx.Context]{
				Contexts: map[string]cfgovctx.Context{"target": {Backend: "nacos"}},
			},
			wantCode: apperrors.CodeUsageError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &atomicImportCredentialBackend{values: map[string]string{}}
			f, records, importPath := atomicImportTestSetup(t, backend, tt.context)
			if tt.locked != nil {
				f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
					return update(tt.locked)
				}
			}

			err := runCtxImport(f, importPath, "", false)
			if got := apperrors.AsAppError(err).Code; got != tt.wantCode {
				t.Fatalf("runCtxImport() code = %s, want %s (err=%v)", got, tt.wantCode, err)
			}
			if backend.puts != 0 || backend.deletes != 0 || backend.gets != tt.wantGets {
				t.Fatalf("credential calls = get:%d put:%d delete:%d, want no mutation", backend.gets, backend.puts, backend.deletes)
			}
			intents := 0
			for _, record := range *records {
				if record.Phase == mutationAuditPhaseIntent {
					intents++
				}
			}
			if intents != tt.wantIntents {
				t.Fatalf("mutation intents = %d, want %d", intents, tt.wantIntents)
			}
		})
	}
}

func TestContextImportReadIntentFailureDoesNotTouchCredentialBackend(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	f, _, importPath := atomicImportTestSetup(t, backend, validAtomicImportContext("new-secret"))
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected read intent failure")
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
	}

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("runCtxImport() code = %s, want LOCAL_IO_ERROR (err=%v)", got, err)
	}
	if backend.gets != 0 || backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf("credential calls = get:%d put:%d delete:%d, want 0/0/0", backend.gets, backend.puts, backend.deletes)
	}
}

func TestContextImportReadOutcomeFailureDoesNotMutateCredentialBackend(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	f, _, importPath := atomicImportTestSetup(t, backend, validAtomicImportContext("new-secret"))
	appendCalls := 0
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			appendCalls++
			if appendCalls == 2 {
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected read outcome failure")
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, int64(appendCalls)).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x43}, 64)),
	}

	err := runCtxImport(f, importPath, "", false)

	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("runCtxImport() code = %s, want LOCAL_IO_ERROR (err=%v)", got, err)
	}
	if backend.gets != 1 || backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf("credential calls = get:%d put:%d delete:%d, want 1/0/0", backend.gets, backend.puts, backend.deletes)
	}
	cfg, loadErr := cfgovctx.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, exists := cfg.Contexts["target"]; exists {
		t.Fatalf("context was imported after failed credential read outcome")
	}
}

func TestContextImportConfigFailureDeletesNewCredentialWithUncanceledCompensation(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	item := validAtomicImportContext("new-secret")
	f, records, importPath := atomicImportTestSetup(t, backend, item)
	parent, cancel := context.WithCancel(context.Background())
	f.commandCtx = parent
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected config commit failure", errors.New("disk failure"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg := &corectx.Config[cfgovctx.Context]{Contexts: map[string]cfgovctx.Context{}}
		if err := update(cfg); err != nil {
			return err
		}
		cancel()
		return configErr
	}

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v, records=%#v)", got, apperrors.CodeLocalIOError, err, *records)
	}
	if _, exists := backend.values["target"]; exists {
		t.Fatalf("new credential was not deleted: %#v", backend.values)
	}
	if backend.puts != 1 || backend.deletes != 1 {
		t.Fatalf("credential calls = put:%d delete:%d, want 1/1", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodeLocalIOError, 0, 1, 0, "succeeded")
}

func TestContextImportConfigFailureRestoresExistingCredential(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{"target": "old-secret"}}
	f, records, importPath := atomicImportTestSetup(t, backend, validAtomicImportContext("new-secret"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected config commit failure", errors.New("disk failure"))
	f.contextImport.updateContexts = failingAtomicImportUpdate(configErr)

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v, records=%#v)", got, apperrors.CodeLocalIOError, err, *records)
	}
	if got := backend.values["target"]; got != "old-secret" {
		t.Fatalf("credential = %q, want restored old value", got)
	}
	if backend.puts != 2 || backend.deletes != 0 {
		t.Fatalf("credential calls = put:%d delete:%d, want 2/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodeLocalIOError, 0, 1, 0, "succeeded")
}

func TestContextImportCompensationFailureReturnsPartialFailureAndAuditsUncertainOutcome(t *testing.T) {
	backend := &atomicImportCredentialBackend{
		values:    map[string]string{},
		deleteErr: errors.New("injected credential rollback failure"),
	}
	f, records, importPath := atomicImportTestSetup(t, backend, validAtomicImportContext("new-secret"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected config commit failure", errors.New("disk failure"))
	f.contextImport.updateContexts = failingAtomicImportUpdate(configErr)

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v, records=%#v)", got, apperrors.CodePartialFailure, err, *records)
	}
	if !strings.Contains(err.Error(), "injected config commit failure") ||
		!strings.Contains(err.Error(), "injected credential rollback failure") {
		t.Fatalf("partial failure does not preserve both causes: %v", err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want uncertain new value retained by failed compensation", got)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 1, "incomplete")
}

func TestContextImportPostCommitErrorKeepsCommittedCredential(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	item := validAtomicImportContext("new-secret")
	f, records, importPath := atomicImportTestSetup(t, backend, item)
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected post-commit failure", errors.New("permission sync failure"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		if err := cfgovctx.Update(update); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if !strings.Contains(err.Error(), "was committed") {
		t.Fatalf("runCtxImport() error = %v, want committed-state reconciliation", err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want committed new value", got)
	}
	cfg, loadErr := cfgovctx.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	stored := cfg.Contexts["target"]
	if stored.Server != item.Server || stored.Backend != item.Backend ||
		stored.Password != credstore.EncodeRef(credentialBackendEncrypted) ||
		stored.CredentialBackend != credentialBackendEncrypted {
		t.Fatalf("stored context = %#v, want imported context with credential reference", stored)
	}
	if backend.deletes != 0 || backend.puts != 1 {
		t.Fatalf("credential calls = put:%d delete:%d, want 1/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusPartialFailed, apperrors.CodePartialFailure, 1, 0, 0, "not-safe")
}

func TestContextImportSameBackendCredentialRotationPostCommitErrorKeepsDesiredSecret(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{"target": "old-secret"}}
	item := validAtomicImportContext("new-secret")
	f, records, importPath := atomicImportTestSetup(t, backend, item)
	existing := item
	existing.Password = credstore.EncodeRef(credentialBackendEncrypted)
	if err := cfgovctx.Set("target", existing); err != nil {
		t.Fatal(err)
	}
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected post-commit failure", errors.New("permission sync failure"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		if err := cfgovctx.Update(update); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxImport(f, importPath, "", true)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want committed rotated value", got)
	}
	if backend.puts != 1 || backend.deletes != 0 {
		t.Fatalf("credential calls = put:%d delete:%d, want 1/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusPartialFailed, apperrors.CodePartialFailure, 1, 0, 0, "not-safe")
}

func TestContextImportPostCommitErrorWithoutExternalCredentialIsReconciled(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	item := validAtomicImportContext(redactedCredential)
	f, records, importPath := atomicImportTestSetup(t, backend, item)
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected post-commit failure", errors.New("permission sync failure"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		if err := cfgovctx.Update(update); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if !strings.Contains(err.Error(), "was committed") {
		t.Fatalf("runCtxImport() error = %v, want committed-state reconciliation", err)
	}
	cfg, loadErr := cfgovctx.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	stored := cfg.Contexts["target"]
	if stored.Password != "" || stored.CredentialBackend != credentialBackendEncrypted {
		t.Fatalf("stored context = %#v, want committed redacted credential context", stored)
	}
	if backend.gets != 0 || backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf("external credential calls = get:%d put:%d delete:%d, want none", backend.gets, backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusPartialFailed, apperrors.CodePartialFailure, 1, 0, 0, "")
}

func TestContextImportDivergentCommitStateDoesNotRiskCredentialRollback(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	f, records, importPath := atomicImportTestSetup(t, backend, validAtomicImportContext("new-secret"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected divergent commit failure", errors.New("unknown commit state"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg, err := cfgovctx.Load()
		if err != nil {
			return err
		}
		if err := update(cfg); err != nil {
			return err
		}
		if err := cfgovctx.Update(func(actual *corectx.Config[cfgovctx.Context]) error {
			actual.Contexts["target"] = cfgovctx.Context{
				Base:    corectx.Base{Server: "http://divergent.example:8848"},
				Backend: "nacos",
			}
			return nil
		}); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want retained new value", got)
	}
	cfg, loadErr := cfgovctx.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if got := cfg.Contexts["target"].Server; got != "http://divergent.example:8848" {
		t.Fatalf("stored context server = %q, want divergent committed state", got)
	}
	if backend.deletes != 0 || backend.puts != 1 {
		t.Fatalf("credential calls = put:%d delete:%d, want 1/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 1, "not-safe")
}

func TestContextImportUnreadableCommitStateAuditsUncertainWithoutRollback(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	f, records, importPath := atomicImportTestSetup(t, backend, validAtomicImportContext("new-secret"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected unknown commit failure", errors.New("unknown commit state"))
	configPath := filepath.Join(filepath.Dir(importPath), "config.yaml")
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg := &corectx.Config[cfgovctx.Context]{Contexts: map[string]cfgovctx.Context{}}
		if err := update(cfg); err != nil {
			return err
		}
		if err := os.WriteFile(configPath, []byte("contexts: [\n"), 0o600); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want retained value when commit state is unreadable", got)
	}
	if backend.deletes != 0 || backend.puts != 1 {
		t.Fatalf("credential calls = put:%d delete:%d, want 1/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 1, "not-safe")
}

func TestContextImportVaultFailureDoesNotDeleteSharedSlot(t *testing.T) {
	backend := &atomicImportCredentialBackend{name: "vault", values: map[string]string{}}
	item := validAtomicImportContext("shared-secret")
	item.CredentialBackend = "vault"
	item.VaultAddr = "https://vault.example/"
	item.VaultPath = "/team/app/"
	item.VaultNamespace = " team-a "
	f, records, importPath := atomicImportTestSetup(t, backend, item)
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected owner takeover failure", errors.New("unknown commit state"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg, err := cfgovctx.Load()
		if err != nil {
			return err
		}
		if err := update(cfg); err != nil {
			return err
		}
		if err := cfgovctx.Update(func(actual *corectx.Config[cfgovctx.Context]) error {
			actual.Contexts["other-owner"] = vaultReferenceContext(
				" https://vault.example ",
				"team/app",
				"team-a",
			)
			return nil
		}); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxImport(f, importPath, "", false)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("runCtxImport() code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "shared-secret" {
		t.Fatalf("Vault credential = %q, want written value preserved", got)
	}
	if backend.gets != 1 || backend.puts != 1 || backend.deletes != 0 {
		t.Fatalf("Vault calls = get:%d put:%d delete:%d, want 1/1/0", backend.gets, backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 1, "not-safe")
}

func TestCtxSetConfigFailureRestoresExistingCredential(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{"target": "old-secret"}}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected config commit failure", errors.New("disk failure"))
	f.contextImport.updateContexts = failingAtomicImportUpdate(configErr)

	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"ctx", "set", "target",
		"--credential-backend", credentialBackendEncrypted,
		"--password", "new-secret",
	})
	err := cmd.Execute()
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("ctx set code = %s, want %s (err=%v)", got, apperrors.CodeLocalIOError, err)
	}
	if got := backend.values["target"]; got != "old-secret" {
		t.Fatalf("credential = %q, want restored old value", got)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodeLocalIOError, 0, 1, 0, "succeeded")
}

func TestCtxSetCompensationFailureAuditsUncertainCredential(t *testing.T) {
	backend := &atomicImportCredentialBackend{
		values: map[string]string{"target": "old-secret"},
		putError: func(call int) error {
			if call == 2 {
				return errors.New("injected credential rollback failure")
			}
			return nil
		},
	}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected config commit failure", errors.New("disk failure"))
	f.contextImport.updateContexts = failingAtomicImportUpdate(configErr)

	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"ctx", "set", "target",
		"--credential-backend", credentialBackendEncrypted,
		"--password", "new-secret",
	})
	err := cmd.Execute()
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("ctx set code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want uncertain new value", got)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 1, "incomplete")
}

func TestCtxSetPostCommitErrorWithoutExternalCredentialIsReconciled(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected post-commit failure", errors.New("permission sync failure"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		if err := cfgovctx.Update(update); err != nil {
			return err
		}
		return configErr
	}

	err := executeAtomicCtxSet(f, "plain-yaml", "")
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("ctx set code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if !strings.Contains(err.Error(), "was committed") {
		t.Fatalf("ctx set error = %v, want committed-state reconciliation", err)
	}
	cfg, loadErr := cfgovctx.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	stored := cfg.Contexts["target"]
	if stored.Password != "" || stored.CredentialBackend != "plain-yaml" {
		t.Fatalf("stored context = %#v, want committed context without external credential", stored)
	}
	if backend.gets != 0 || backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf("external credential calls = get:%d put:%d delete:%d, want none", backend.gets, backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusPartialFailed, apperrors.CodePartialFailure, 1, 0, 0, "")
}

func TestCtxSetSameBackendCredentialRotationPostCommitErrorKeepsDesiredSecret(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{"target": "old-secret"}}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	if err := cfgovctx.Set("target", cfgovctx.Context{
		Base: corectx.Base{
			Server:            "http://127.0.0.1:8848",
			Password:          credstore.EncodeRef(credentialBackendEncrypted),
			CredentialBackend: credentialBackendEncrypted,
			OTLPRedact:        true,
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected post-commit failure", errors.New("permission sync failure"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		if err := cfgovctx.Update(update); err != nil {
			return err
		}
		return configErr
	}

	err := executeAtomicCtxSet(f, credentialBackendEncrypted, "new-secret")
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("ctx set code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want committed rotated value", got)
	}
	if backend.puts != 1 || backend.deletes != 0 {
		t.Fatalf("credential calls = put:%d delete:%d, want 1/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusPartialFailed, apperrors.CodePartialFailure, 1, 0, 0, "not-safe")
}

func TestCtxSetSameBackendCredentialWriteErrorReconcilesStoredValue(t *testing.T) {
	tests := []struct {
		name             string
		afterWrite       bool
		wantCode         apperrors.ErrorCode
		wantSecret       string
		wantStatus       string
		wantSucceeded    int
		wantFailed       int
		wantCompensation string
	}{
		{
			name:             "write not committed",
			wantCode:         apperrors.CodeCredentialStoreError,
			wantSecret:       "old-secret",
			wantStatus:       audit.StatusFailed,
			wantFailed:       1,
			wantCompensation: "succeeded",
		},
		{
			name:             "write committed before error",
			afterWrite:       true,
			wantCode:         apperrors.CodePartialFailure,
			wantSecret:       "new-secret",
			wantStatus:       audit.StatusPartialFailed,
			wantSucceeded:    1,
			wantCompensation: "not-safe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &atomicImportCredentialBackend{values: map[string]string{"target": "old-secret"}}
			writeErr := func(int) error { return errors.New("injected credential write failure") }
			if tt.afterWrite {
				backend.putAfterError = writeErr
			} else {
				backend.putError = writeErr
			}
			f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
			if err := cfgovctx.Set("target", cfgovctx.Context{
				Base: corectx.Base{
					Server:            "http://127.0.0.1:8848",
					Password:          credstore.EncodeRef(credentialBackendEncrypted),
					CredentialBackend: credentialBackendEncrypted,
					OTLPRedact:        true,
				},
				Backend: "nacos",
			}); err != nil {
				t.Fatal(err)
			}
			configErr := apperrors.New(apperrors.CodeLocalIOError, "injected config failure", errors.New("disk failure"))
			f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
				cfg, err := cfgovctx.Load()
				if err != nil {
					return err
				}
				if err := update(cfg); err != nil {
					return err
				}
				return configErr
			}

			err := executeAtomicCtxSet(f, credentialBackendEncrypted, "new-secret")
			if got := apperrors.AsAppError(err).Code; got != tt.wantCode {
				t.Fatalf("ctx set code = %s, want %s (err=%v)", got, tt.wantCode, err)
			}
			if got := backend.values["target"]; got != tt.wantSecret {
				t.Fatalf("credential = %q, want %q", got, tt.wantSecret)
			}
			if backend.puts != 1 || backend.deletes != 0 {
				t.Fatalf("credential calls = put:%d delete:%d, want 1/0", backend.puts, backend.deletes)
			}
			assertCredentialMutationOutcome(
				t,
				*records,
				tt.wantStatus,
				tt.wantCode,
				tt.wantSucceeded,
				tt.wantFailed,
				0,
				tt.wantCompensation,
			)
		})
	}
}

func TestCtxSetDivergentCommitStateAuditsUncertainWithoutRollback(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected divergent commit failure", errors.New("unknown commit state"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg, err := cfgovctx.Load()
		if err != nil {
			return err
		}
		if err := update(cfg); err != nil {
			return err
		}
		if err := cfgovctx.Update(func(actual *corectx.Config[cfgovctx.Context]) error {
			actual.Contexts["target"] = cfgovctx.Context{
				Base:    corectx.Base{Server: "http://divergent.example:8848"},
				Backend: "nacos",
			}
			return nil
		}); err != nil {
			return err
		}
		return configErr
	}

	err := executeAtomicCtxSet(f, credentialBackendEncrypted, "new-secret")
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("ctx set code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "new-secret" {
		t.Fatalf("credential = %q, want retained value for divergent config", got)
	}
	if backend.puts != 1 || backend.deletes != 0 {
		t.Fatalf("credential calls = put:%d delete:%d, want 1/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 1, "not-safe")
}

func TestCtxSetVaultOwnerTakeoverRefusesAutomaticRestore(t *testing.T) {
	backend := &atomicImportCredentialBackend{
		name:   "vault",
		values: map[string]string{"target": "old-secret"},
	}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected owner takeover failure", errors.New("unknown commit state"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg, err := cfgovctx.Load()
		if err != nil {
			return err
		}
		if err := update(cfg); err != nil {
			return err
		}
		if err := cfgovctx.Update(func(actual *corectx.Config[cfgovctx.Context]) error {
			actual.Contexts["other-owner"] = vaultReferenceContext(
				" https://vault.example ",
				"team/app",
				"team-a",
			)
			return nil
		}); err != nil {
			return err
		}
		return configErr
	}

	err := executeAtomicVaultCtxSet(f, "shared-secret")
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("ctx set code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if got := backend.values["target"]; got != "shared-secret" {
		t.Fatalf("Vault credential = %q, want written value preserved", got)
	}
	if backend.gets != 1 || backend.puts != 1 || backend.deletes != 0 {
		t.Fatalf("Vault calls = get:%d put:%d delete:%d, want 1/1/0", backend.gets, backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 1, "not-safe")
}

func TestCredentialMigrationSecondWriteFailureCompensatesAllAttemptedKeys(t *testing.T) {
	backend := &atomicImportCredentialBackend{
		values: map[string]string{},
		putError: func(call int) error {
			if call == 2 {
				return errors.New("injected second credential write failure")
			}
			return nil
		},
	}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	seedLiteralMigrationContexts(t)

	err := runCtxMigrateCredentials(f, migrateCredentialsOptions{toBackend: credentialBackendEncrypted})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeCredentialStoreError {
		t.Fatalf("credential migration code = %s, want %s (err=%v)", got, apperrors.CodeCredentialStoreError, err)
	}
	if len(backend.values) != 0 {
		t.Fatalf("credential compensation left values: %#v", backend.values)
	}
	assertLiteralMigrationContexts(t)
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodeCredentialStoreError, 0, 2, 0, "succeeded")
}

func TestCredentialMigrationConfigFailureRestoresTargetCredentials(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{
		"alpha": "previous-alpha",
		"beta":  "previous-beta",
	}}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	seedLiteralMigrationContexts(t)
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected config commit failure", errors.New("disk failure"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg, err := cfgovctx.Load()
		if err != nil {
			return err
		}
		if err := update(cfg); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxMigrateCredentials(f, migrateCredentialsOptions{toBackend: credentialBackendEncrypted})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("credential migration code = %s, want %s (err=%v)", got, apperrors.CodeLocalIOError, err)
	}
	if backend.values["alpha"] != "previous-alpha" || backend.values["beta"] != "previous-beta" {
		t.Fatalf("credentials were not restored: %#v", backend.values)
	}
	assertLiteralMigrationContexts(t)
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodeLocalIOError, 0, 2, 0, "succeeded")
}

func TestCredentialMigrationCompensationFailureAuditsAllAttemptedKeysUncertain(t *testing.T) {
	backend := &atomicImportCredentialBackend{
		values:    map[string]string{},
		deleteErr: errors.New("injected credential rollback failure"),
		putError: func(call int) error {
			if call == 2 {
				return errors.New("injected second credential write failure")
			}
			return nil
		},
	}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	seedLiteralMigrationContexts(t)

	err := runCtxMigrateCredentials(f, migrateCredentialsOptions{toBackend: credentialBackendEncrypted})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("credential migration code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	assertLiteralMigrationContexts(t)
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 2, "incomplete")
}

func TestCredentialMigrationDivergentCommitStateMarksAllWritesUncertain(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{}}
	f, records, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	seedLiteralMigrationContexts(t)
	configErr := apperrors.New(apperrors.CodeLocalIOError, "injected divergent config failure", errors.New("unknown commit state"))
	f.contextImport.updateContexts = func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg, err := cfgovctx.Load()
		if err != nil {
			return err
		}
		if err := update(cfg); err != nil {
			return err
		}
		if err := cfgovctx.Update(func(actual *corectx.Config[cfgovctx.Context]) error {
			item := actual.Contexts["alpha"]
			item.Server = "http://divergent.example:8848"
			actual.Contexts["alpha"] = item
			return nil
		}); err != nil {
			return err
		}
		return configErr
	}

	err := runCtxMigrateCredentials(f, migrateCredentialsOptions{toBackend: credentialBackendEncrypted})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("credential migration code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if backend.values["alpha"] != "literal-alpha" || backend.values["beta"] != "literal-beta" {
		t.Fatalf("written credentials changed during unsafe reconciliation: %#v", backend.values)
	}
	if backend.puts != 2 || backend.deletes != 0 {
		t.Fatalf("credential calls = put:%d delete:%d, want 2/0", backend.puts, backend.deletes)
	}
	assertCredentialMutationOutcome(t, *records, audit.StatusFailed, apperrors.CodePartialFailure, 0, 0, 2, "not-safe")
}

func TestCredentialCompensationHoldsContextLock(t *testing.T) {
	t.Run("context target", func(t *testing.T) {
		backend := &atomicImportCredentialBackend{values: map[string]string{"target": "new-secret"}}
		f, _, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
		transaction := &credentialMutationTransaction{
			backend: backend,
			writes:  []credentialMutationWrite{{name: "target", written: "new-secret"}},
		}
		operationErr := apperrors.New(apperrors.CodeLocalIOError, "injected config failure", errors.New("disk failure"))

		assertConfigUpdateBlockedDuringCredentialCompensation(t, backend, func() error {
			_, _, err := reconcileContextSetCredentialFailure(
				context.Background(),
				f,
				transaction,
				"target",
				contextTargetState{},
				validAtomicImportContext(credstore.EncodeRef(credentialBackendEncrypted)),
				operationErr,
			)
			return err
		})
		if _, exists := backend.values["target"]; exists {
			t.Fatalf("credential was not compensated: %#v", backend.values)
		}
	})

	t.Run("credential migration", func(t *testing.T) {
		backend := &atomicImportCredentialBackend{values: map[string]string{}}
		f, _, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
		seedLiteralMigrationContexts(t)
		cfg, err := cfgovctx.Load()
		if err != nil {
			t.Fatal(err)
		}
		candidates, err := credentialMigrationCandidates(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		transaction := &credentialMutationTransaction{backend: backend}
		for _, candidate := range candidates {
			backend.values[candidate.name] = candidate.password
			transaction.writes = append(transaction.writes, credentialMutationWrite{
				name:    candidate.name,
				written: candidate.password,
			})
		}
		operationErr := apperrors.New(apperrors.CodeLocalIOError, "injected config failure", errors.New("disk failure"))

		assertConfigUpdateBlockedDuringCredentialCompensation(t, backend, func() error {
			_, _, err := reconcileCredentialMigrationFailure(
				context.Background(),
				f,
				transaction,
				candidates,
				credentialBackendEncrypted,
				credentialMutationProgress{succeeded: len(candidates)},
				operationErr,
			)
			return err
		})
		if len(backend.values) != 0 {
			t.Fatalf("credentials were not compensated: %#v", backend.values)
		}
	})
}

func TestCredentialCompensationRefusesToOverwriteNewerValue(t *testing.T) {
	backend := &atomicImportCredentialBackend{values: map[string]string{"target": "newer-secret"}}
	f, _, _ := atomicImportTestSetup(t, backend, validAtomicImportContext("unused"))
	transaction := &credentialMutationTransaction{
		backend: backend,
		writes: []credentialMutationWrite{{
			name:     "target",
			previous: "old-secret",
			written:  "transaction-secret",
			existed:  true,
		}},
	}
	operationErr := apperrors.New(apperrors.CodeLocalIOError, "injected config failure", errors.New("disk failure"))
	progress, compensationStatus, err := reconcileContextSetCredentialFailure(
		context.Background(),
		f,
		transaction,
		"target",
		contextTargetState{},
		validAtomicImportContext(credstore.EncodeRef(credentialBackendEncrypted)),
		operationErr,
	)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("reconciliation code = %s, want %s (err=%v)", got, apperrors.CodePartialFailure, err)
	}
	if progress != (credentialMutationProgress{uncertain: 1}) || compensationStatus != "incomplete" {
		t.Fatalf("progress=%+v compensation=%q, want uncertain/incomplete", progress, compensationStatus)
	}
	if got := backend.values["target"]; got != "newer-secret" {
		t.Fatalf("credential = %q, want newer value preserved", got)
	}
	if backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf("credential mutations = put:%d delete:%d, want none", backend.puts, backend.deletes)
	}
}

func seedLiteralMigrationContexts(t *testing.T) {
	t.Helper()
	for _, name := range []string{"alpha", "beta"} {
		if err := cfgovctx.Set(name, cfgovctx.Context{
			Base:    corectx.Base{Server: "http://127.0.0.1:8848", Password: "literal-" + name},
			Backend: "nacos",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func assertLiteralMigrationContexts(t *testing.T) {
	t.Helper()
	cfg, err := cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if got := cfg.Contexts[name].Password; got != "literal-"+name {
			t.Fatalf("context %s credential = %q, want unchanged literal", name, got)
		}
	}
}

func assertCredentialMutationOutcome(
	t *testing.T,
	records []mutationAuditRecord,
	wantStatus string,
	wantCode apperrors.ErrorCode,
	wantSucceeded int,
	wantFailed int,
	wantUncertain int,
	wantCompensation string,
) {
	t.Helper()
	mutationRecords := make([]mutationAuditRecord, 0, 2)
	for _, record := range records {
		if record.Kind == mutationAuditKind {
			mutationRecords = append(mutationRecords, record)
		}
	}
	if len(mutationRecords) != 2 || mutationRecords[1].Outcome == nil {
		t.Fatalf("mutation records = %#v, want intent and outcome", mutationRecords)
	}
	outcome := mutationRecords[1].Outcome
	if outcome.Status != wantStatus ||
		outcome.ErrorCode != string(wantCode) ||
		outcome.Succeeded != wantSucceeded ||
		outcome.Failed != wantFailed ||
		outcome.Uncertain != wantUncertain ||
		outcome.CompensationStatus != wantCompensation {
		t.Fatalf(
			"outcome = %#v, want status=%s code=%s succeeded=%d failed=%d uncertain=%d compensation=%s",
			outcome,
			wantStatus,
			wantCode,
			wantSucceeded,
			wantFailed,
			wantUncertain,
			wantCompensation,
		)
	}
}

func atomicImportTestSetup(
	t *testing.T,
	backend *atomicImportCredentialBackend,
	item cfgovctx.Context,
) (*cliFlags, *[]mutationAuditRecord, string) {
	t.Helper()
	home := t.TempDir()
	prepareMutationAuditTestParent(t, home)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	importPath := writeAtomicImportDocument(t, home, item)

	records := make([]mutationAuditRecord, 0, 2)
	f := newDefaultFlags()
	f.resolveOperator = func() (string, error) { return "admin@host", nil }
	f.Yes = true
	f.NonInter = true
	f.Ticket = "TEST-1"
	f.AllowCtxChange = true
	f.mutationAuditPath = filepath.Join(home, "audit.jsonl")
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(path string, record mutationAuditRecord, options audit.Options) (audit.AppendResult, error) {
			result, err := audit.AppendRecordWithResult(path, record, options)
			if err != nil {
				return result, err
			}
			records = append(records, record)
			return result, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 4096)),
	}
	f.contextImport = &contextImportRuntime{
		newCredentialBackend: func(cfgovctx.Context) (credstore.Backend, error) {
			return backend, nil
		},
		rollbackTimeout: time.Second,
	}
	return f, &records, importPath
}

func validAtomicImportContext(password string) cfgovctx.Context {
	return cfgovctx.Context{
		Base: corectx.Base{
			Server:            "http://127.0.0.1:8848",
			Password:          password,
			CredentialBackend: credentialBackendEncrypted,
			Roles:             map[string]string{"admin@host": safety.RoleAdmin},
		},
		Backend: "nacos",
	}
}

func writeAtomicImportDocument(t *testing.T, dir string, item cfgovctx.Context) string {
	t.Helper()
	data, err := yaml.Marshal(contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       "target",
		Context:    item,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "context.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func failingAtomicImportUpdate(
	configErr error,
) func(func(*corectx.Config[cfgovctx.Context]) error) error {
	return func(update func(*corectx.Config[cfgovctx.Context]) error) error {
		cfg := &corectx.Config[cfgovctx.Context]{Contexts: map[string]cfgovctx.Context{}}
		if err := update(cfg); err != nil {
			return err
		}
		return configErr
	}
}

func executeAtomicCtxSet(f *cliFlags, credentialBackend, password string) error {
	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"ctx", "set", "target",
		"--credential-backend", credentialBackend,
		"--password", password,
	})
	return cmd.Execute()
}

func executeAtomicVaultCtxSet(f *cliFlags, password string) error {
	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"ctx", "set", "target",
		"--credential-backend", "vault",
		"--password", password,
		"--vault-addr", "https://vault.example/",
		"--vault-path", "/team/app/",
		"--vault-namespace", " team-a ",
	})
	return cmd.Execute()
}

func vaultReferenceContext(addr, path, namespace string) cfgovctx.Context {
	return cfgovctx.Context{
		Base: corectx.Base{
			Password:          credstore.EncodeRef("vault"),
			CredentialBackend: "vault",
			VaultAddr:         addr,
			VaultPath:         path,
			VaultNamespace:    namespace,
		},
		Backend: "nacos",
	}
}

func assertConfigUpdateBlockedDuringCredentialCompensation(
	t *testing.T,
	backend *atomicImportCredentialBackend,
	reconcile func() error,
) {
	t.Helper()
	compensationStarted := make(chan struct{})
	releaseCompensation := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCompensation) }) }
	defer release()
	backend.beforeDelete = func(call int) {
		if call != 1 {
			return
		}
		close(compensationStarted)
		<-releaseCompensation
	}

	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- reconcile() }()
	select {
	case <-compensationStarted:
	case <-time.After(5 * time.Second):
		release()
		t.Fatalf("credential compensation did not start")
	}

	updateEntered := make(chan struct{})
	updateDone := make(chan error, 1)
	go func() {
		updateDone <- cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
			close(updateEntered)
			cfg.Contexts["racer"] = cfgovctx.Context{Backend: "nacos"}
			return nil
		})
	}()
	enteredBeforeRelease := false
	select {
	case <-updateEntered:
		enteredBeforeRelease = true
	case <-time.After(300 * time.Millisecond):
	}
	release()

	select {
	case err := <-reconcileDone:
		if err == nil {
			t.Fatal("reconciliation unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconciliation did not finish")
	}
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatalf("concurrent context update failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent context update did not finish")
	}
	if enteredBeforeRelease {
		t.Fatal("concurrent context update entered while credential compensation was still running")
	}
}
