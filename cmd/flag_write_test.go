package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
)

func TestFlagCreateUpdatePlanningErrors(t *testing.T) {
	t.Parallel()
	current := []flag.FeatureFlag{{Key: "checkout", Enabled: true, Variants: []flag.Variant{{Name: "on", Value: "true"}}}}
	local := flag.FeatureFlag{Key: "checkout", Enabled: true, Variants: []flag.Variant{{Name: "off", Value: "false"}}}
	if _, err := planSingleFlagSet(flagWriteOptions{action: "create"}, current, local); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("create existing error = %v, want validation failed", err)
	}
	if _, err := planSingleFlagSet(flagWriteOptions{action: "update"}, nil, local); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("update missing error = %v, want validation failed", err)
	}
	forced, err := planSingleFlagSet(flagWriteOptions{action: "create", force: true}, current, local)
	if err != nil {
		t.Fatalf("force create error = %v", err)
	}
	if len(forced) != 1 || forced[0].Variants[0].Name != "off" {
		t.Fatalf("forced = %#v", forced)
	}
}

func TestFlagDeleteKeyAllUsage(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	if err := runFlagDelete(context.Background(), f, flagWriteOptions{app: "app"}); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("missing selector error = %v, want usage", err)
	}
	if err := runFlagDelete(context.Background(), f, flagWriteOptions{app: "app", key: "k", all: true}); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("both selectors error = %v, want usage", err)
	}
}

func TestForceDoesNotBypassDeepFlagValidation(t *testing.T) {
	t.Parallel()
	current := flagSetResult{App: "app", Count: 1, SHA256: "remote", Flags: []flag.FeatureFlag{{Key: "checkout"}}}
	next := []flag.FeatureFlag{{Key: "checkout", DefaultVariant: "missing", Variants: []flag.Variant{{Name: "on", Value: "true"}}}}
	_, _, err := plannedFlagSetWrite(fakeFlagStore{}, "app", safety.R1, "create", current, next)
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("plannedFlagSetWrite error = %v, want validation failed", err)
	}
}

func TestFlagImportDuplicateKeyDeepValidation(t *testing.T) {
	t.Parallel()
	flags := []flag.FeatureFlag{{Key: "checkout"}, {Key: "checkout"}}
	_, _, err := plannedFlagSetWrite(fakeFlagStore{}, "app", safety.R1, "import", flagSetResult{App: "app"}, flags)
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("duplicate import error = %v, want validation failed", err)
	}
}

func TestFlagDeleteAuthorizationLadder(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"
	if err := authorize(f, safety.R2, cfgovctx.Context{}, allowProductionFlagDelete); err != nil {
		t.Fatalf("unprotected flag delete authorize error = %v", err)
	}
	meta := cfgovctx.Context{}
	meta.Protected = true
	if err := authorize(f, safety.R2, meta, allowProductionFlagDelete); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("protected without allow error = %v, want authorization required", err)
	}
	wrongFlags := []func(){
		func() { f.AllowPrune = true },
		func() { f.AllowNSDel = true },
		func() { f.AllowSvcDereg = true },
		func() { f.AllowRuleDel = true },
	}
	for _, setWrong := range wrongFlags {
		f.AllowPrune, f.AllowNSDel, f.AllowSvcDereg, f.AllowRuleDel = false, false, false, false
		setWrong()
		if err := authorize(f, safety.R2, meta, allowProductionFlagDelete); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
			t.Fatalf("wrong allow error = %v, want authorization required", err)
		}
	}
	f.AllowPrune, f.AllowNSDel, f.AllowSvcDereg, f.AllowRuleDel = false, false, false, false
	f.AllowFlagDel = true
	if err := authorize(f, safety.R2, meta, allowProductionFlagDelete); err != nil {
		t.Fatalf("protected with flag allow error = %v", err)
	}
}

func TestMandatoryFlagBackupRejectsNoBackup(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.NoBackup = true
	err := validateMandatoryFlagBackup(f, []plannedFlagWrite{{backupBefore: true}})
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestApplyFlagWritesCASConflict(t *testing.T) {
	backend := newFlagWriteBackend([]byte(`[{"key":"checkout","enabled":true}]`), "rev1")
	current := flagSetResult{App: "app", Count: 1, Key: "FEATURE_FLAG_GROUP/app-flags", Revision: "rev1", SHA256: sha256Bytes(backend.content), Flags: []flag.FeatureFlag{{Key: "checkout", Enabled: true}}}
	next := []flag.FeatureFlag{{Key: "checkout", Enabled: false}}
	write, plan, err := plannedFlagSetWrite(backend, "app", safety.R1, "update", current, next)
	if err != nil {
		t.Fatalf("plannedFlagSetWrite error = %v", err)
	}
	applyExpectedFlagRevision("stale", &write, &plan)
	f := newDefaultFlags()
	f.Yes = true
	err = applyFlagWrites(context.Background(), f, backend, cfgovctx.Context{}, plan, []plannedFlagWrite{write}, safety.R1, "")
	if apperrors.AsAppError(err).Code != apperrors.CodeConflict {
		t.Fatalf("applyFlagWrites error = %v, want conflict", err)
	}
}

func TestApplyFlagWritesSkipsIdempotentWrite(t *testing.T) {
	payload := []byte(`[{"key":"checkout","enabled":true}]`)
	backend := newFlagWriteBackend(payload, "rev1")
	current := flagSetResult{App: "app", Count: 1, Key: "FEATURE_FLAG_GROUP/app-flags", Revision: "rev1", SHA256: sha256Bytes(payload), Flags: []flag.FeatureFlag{{Key: "checkout", Enabled: true}}}
	write, plan, err := plannedFlagSetWrite(backend, "app", safety.R1, "update", current, current.Flags)
	if err != nil {
		t.Fatalf("plannedFlagSetWrite error = %v", err)
	}
	f := newDefaultFlags()
	f.Yes = true
	if err := applyFlagWrites(context.Background(), f, backend, cfgovctx.Context{}, plan, []plannedFlagWrite{write}, safety.R1, ""); err != nil {
		t.Fatalf("applyFlagWrites error = %v", err)
	}
	if backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf("writes = put %d delete %d, want skip", backend.puts, backend.deletes)
	}
}

func TestReadRollbackFlagsFromFileAndDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "flags.json")
	if err := os.WriteFile(file, []byte(`[{"key":"checkout"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	flags, err := readRollbackFlags(file)
	if err != nil || len(flags) != 1 {
		t.Fatalf("readRollbackFlags(file) = %#v, %v", flags, err)
	}
	flags, err = readRollbackFlags(dir)
	if err != nil || len(flags) != 1 {
		t.Fatalf("readRollbackFlags(dir) = %#v, %v", flags, err)
	}
}

type fakeFlagStore struct{}

func (fakeFlagStore) FlagCoordinate(app string) (cfgov.Coordinate, error) {
	return cfgov.Coordinate{Namespace: "ns", Key: "FEATURE_FLAG_GROUP/" + app + "-flags"}, nil
}

type flagWriteBackend struct {
	content  []byte
	revision string
	puts     int
	deletes  int
}

func newFlagWriteBackend(content []byte, revision string) *flagWriteBackend {
	return &flagWriteBackend{content: append([]byte(nil), content...), revision: revision}
}

func (b *flagWriteBackend) FlagCoordinate(app string) (cfgov.Coordinate, error) {
	return cfgov.Coordinate{Namespace: "ns", Key: "FEATURE_FLAG_GROUP/" + app + "-flags"}, nil
}

func (b *flagWriteBackend) ValidateKey(string) error { return nil }

func (b *flagWriteBackend) Get(context.Context, cfgov.Coordinate) (cfgov.Blob, error) {
	if b.content == nil {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeResourceNotFound, "not found", nil)
	}
	return cfgov.Blob{Content: append([]byte(nil), b.content...), Revision: b.revision}, nil
}

func (b *flagWriteBackend) Put(_ context.Context, req cfgov.PutRequest) (cfgov.Blob, error) {
	if req.ExpectedRevision != "" && req.ExpectedRevision != b.revision {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
	}
	b.puts++
	b.content = append([]byte(nil), req.Content...)
	b.revision = sha256Bytes(req.Content)
	return cfgov.Blob{Coordinate: req.Coordinate, Content: b.content, Revision: b.revision}, nil
}

func (b *flagWriteBackend) Delete(_ context.Context, req cfgov.DeleteRequest) error {
	if req.ExpectedRevision != "" && req.ExpectedRevision != b.revision {
		return apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
	}
	b.deletes++
	b.content = nil
	b.revision = ""
	return nil
}

func (b *flagWriteBackend) List(context.Context, cfgov.ListOptions) ([]cfgov.ListItem, error) {
	return nil, nil
}

func (b *flagWriteBackend) History(context.Context, cfgov.Coordinate, cfgov.HistoryOptions) ([]cfgov.HistoryItem, int, error) {
	return nil, 0, nil
}

func (b *flagWriteBackend) Watch(context.Context, cfgov.Coordinate, string, cfgov.WatchOptions) (cfgov.WatchEvent, error) {
	return cfgov.WatchEvent{}, nil
}

func (b *flagWriteBackend) CurrentRevision(context.Context, cfgov.Coordinate) (string, error) {
	return b.revision, nil
}

func (b *flagWriteBackend) Ping(context.Context) error { return nil }

func (b *flagWriteBackend) Describe() cfgov.Description {
	return cfgov.Description{Backend: "fake", Namespace: "ns"}
}

func (b *flagWriteBackend) Capabilities() cfgov.Capabilities {
	return cfgov.Capabilities{SupportsFlags: true}
}
