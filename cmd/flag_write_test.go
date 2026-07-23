package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
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

func TestFlagWritesRequireBackendCAS(t *testing.T) {
	t.Parallel()
	write := plannedFlagWrite{
		current:  flagSetResult{Revision: "rev1"},
		planItem: flagPlanItem{Action: "update"},
	}
	err := validateFlagWriteCapabilities(
		cfgov.Capabilities{Backend: "apollo", SupportsFlags: true, SupportsCAS: false},
		[]plannedFlagWrite{write},
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("Apollo existing flag write error = %v, want not implemented", err)
	}
	if err := validateFlagWriteCapabilities(
		cfgov.Capabilities{Backend: "consul", SupportsFlags: true, SupportsCAS: true},
		[]plannedFlagWrite{write},
	); err != nil {
		t.Fatalf("CAS-capable flag write rejected: %v", err)
	}
	write.planItem.Action = "skip"
	if err := validateFlagWriteCapabilities(
		cfgov.Capabilities{Backend: "nacos", SupportsFlags: true, SupportsCAS: false},
		[]plannedFlagWrite{write},
	); err != nil {
		t.Fatalf("idempotent flag skip rejected: %v", err)
	}
	write.current.Revision = ""
	write.planItem.Action = "create"
	if err := validateFlagWriteCapabilities(
		cfgov.Capabilities{Backend: "apollo", SupportsFlags: true, SupportsCAS: false},
		[]plannedFlagWrite{write},
	); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("Apollo initial flag write error = %v, want not implemented", err)
	}
}

func TestUnsupportedSchemaCASStopsBeforeAuditAndBackend(t *testing.T) {
	backend := newFlagWriteBackend([]byte(`[{"key":"checkout","enabled":true}]`))
	backend.supportsCAS = false
	appendCalls := 0
	f := mutationAuditTestFlags()
	f.Yes = true
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			appendCalls++
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
	}

	flagWrite := plannedFlagWrite{
		current:  flagSetResult{Revision: "rev1"},
		planItem: flagPlanItem{Action: "update"},
	}
	err := applyFlagWrites(
		context.Background(),
		f,
		backend,
		cfgovctx.Context{},
		flagWritePlan{Action: "update"},
		[]plannedFlagWrite{flagWrite},
		safety.R1,
		"",
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("applyFlagWrites() error = %v, want not implemented", err)
	}

	ruleWrite := plannedRuleWrite{
		current:  ruleSetResult{Revision: "rev1"},
		planItem: rulePlanItem{Action: "update"},
	}
	err = applyRuleWrites(
		context.Background(),
		f,
		backend,
		cfgovctx.Context{},
		ruleWritePlan{Action: "update"},
		[]plannedRuleWrite{ruleWrite},
		safety.R1,
		"",
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("applyRuleWrites() error = %v, want not implemented", err)
	}
	initialFlagWrite := plannedFlagWrite{planItem: flagPlanItem{Action: "create"}}
	err = applyFlagWrites(
		context.Background(),
		f,
		backend,
		cfgovctx.Context{},
		flagWritePlan{Action: "create"},
		[]plannedFlagWrite{initialFlagWrite},
		safety.R1,
		"",
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("initial applyFlagWrites() error = %v, want not implemented", err)
	}
	initialRuleWrite := plannedRuleWrite{planItem: rulePlanItem{Action: "create"}}
	err = applyRuleWrites(
		context.Background(),
		f,
		backend,
		cfgovctx.Context{},
		ruleWritePlan{Action: "create"},
		[]plannedRuleWrite{initialRuleWrite},
		safety.R1,
		"",
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("initial applyRuleWrites() error = %v, want not implemented", err)
	}
	if appendCalls != 0 || backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf(
			"unsupported CAS caused side effects: audit=%d put=%d delete=%d",
			appendCalls,
			backend.puts,
			backend.deletes,
		)
	}
}

func TestInitialSchemaWritesUseAtomicAbsencePrecondition(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	f := mutationAuditTestFlags()
	f.Yes = true
	f.mutationAuditPath = filepath.Join(root, "audit.log")
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		appendOrdinary: func(string, any, audit.Options) error { return nil },
		now:            func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random:         bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
	}

	flagBackend := &flagWriteBackend{supportsCAS: true}
	flagCoord := cfgov.Coordinate{Namespace: "ns", Key: "FEATURE_FLAG_GROUP/app-flags"}
	flagItem := flagPlanItem{Key: flagCoord.Key, Action: "create", Coordinate: flagCoord}
	flagWrite := plannedFlagWrite{coord: flagCoord, payload: []byte(`[]`), planItem: flagItem}
	flagPlan := flagWritePlan{
		ResourceType: "flag",
		Action:       "create",
		App:          "app",
		Summary:      flagPlanSummary{Create: 1, Total: 1},
		Items:        []flagPlanItem{flagItem},
	}
	if err := applyFlagWrites(context.Background(), f, flagBackend, cfgovctx.Context{}, flagPlan, []plannedFlagWrite{flagWrite}, safety.R1, ""); err != nil {
		t.Fatalf("applyFlagWrites() error = %v", err)
	}
	if !flagBackend.lastPut.RequireAbsent || flagBackend.lastPut.ExpectedRevision != "" {
		t.Fatalf("initial flag put = %#v, want RequireAbsent only", flagBackend.lastPut)
	}

	ruleBackend := &flagWriteBackend{supportsCAS: true}
	ruleCoord := cfgov.Coordinate{Namespace: "ns", Key: "SENTINEL_GROUP/app-flow-rules"}
	ruleItem := rulePlanItem{Type: rule.TypeFlow, Key: ruleCoord.Key, Action: "create", Coordinate: ruleCoord}
	ruleWrite := plannedRuleWrite{ruleType: rule.TypeFlow, coord: ruleCoord, payload: []byte(`[]`), planItem: ruleItem}
	rulePlan := ruleWritePlan{
		ResourceType: "rule",
		Action:       "create",
		App:          "app",
		Summary:      rulePlanSummary{Create: 1, Total: 1},
		Items:        []rulePlanItem{ruleItem},
	}
	if err := applyRuleWrites(context.Background(), f, ruleBackend, cfgovctx.Context{}, rulePlan, []plannedRuleWrite{ruleWrite}, safety.R1, ""); err != nil {
		t.Fatalf("applyRuleWrites() error = %v", err)
	}
	if !ruleBackend.lastPut.RequireAbsent || ruleBackend.lastPut.ExpectedRevision != "" {
		t.Fatalf("initial rule put = %#v, want RequireAbsent only", ruleBackend.lastPut)
	}
}

func TestApplyFlagWritesCASConflict(t *testing.T) {
	backend := newFlagWriteBackend([]byte(`[{"key":"checkout","enabled":true}]`))
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

func TestApplyFlagWritesIntentFailureDoesNotCallBackend(t *testing.T) {
	backend := newFlagWriteBackend([]byte(`[{"key":"checkout","enabled":true}]`))
	current := flagSetResult{
		App:      "app",
		Count:    1,
		Key:      "FEATURE_FLAG_GROUP/app-flags",
		Revision: "rev1",
		SHA256:   sha256Bytes(backend.content),
		Flags:    []flag.FeatureFlag{{Key: "checkout", Enabled: true}},
	}
	next := []flag.FeatureFlag{{Key: "checkout", Enabled: false}}
	write, plan, err := plannedFlagSetWrite(backend, "app", safety.R1, "update", current, next)
	if err != nil {
		t.Fatalf("plannedFlagSetWrite() error = %v", err)
	}
	f := mutationAuditTestFlags()
	f.Yes = true
	auditRoot := t.TempDir()
	prepareMutationAuditTestParent(t, auditRoot)
	f.mutationAuditPath = filepath.Join(auditRoot, "audit.log")
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected intent failure")
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 16)),
	}
	err = applyFlagWrites(context.Background(), f, backend, cfgovctx.Context{}, plan, []plannedFlagWrite{write}, safety.R1, "")
	if err == nil {
		t.Fatal("applyFlagWrites() error = nil, want intent persistence failure")
	}
	if backend.puts != 0 || backend.deletes != 0 {
		t.Fatalf("backend calls after intent failure = put %d delete %d, want zero", backend.puts, backend.deletes)
	}
}

func TestApplyFlagWritesOrdersIntentTargetOutcome(t *testing.T) {
	backend := newFlagWriteBackend([]byte(`[{"key":"checkout","enabled":true}]`))
	current := flagSetResult{
		App:      "app",
		Count:    1,
		Key:      "FEATURE_FLAG_GROUP/app-flags",
		Revision: "rev1",
		SHA256:   sha256Bytes(backend.content),
		Flags:    []flag.FeatureFlag{{Key: "checkout", Enabled: true}},
	}
	next := []flag.FeatureFlag{{Key: "checkout", Enabled: false}}
	write, plan, err := plannedFlagSetWrite(backend, "app", safety.R1, "update", current, next)
	if err != nil {
		t.Fatalf("plannedFlagSetWrite() error = %v", err)
	}
	var order []string
	backend.onPut = func() { order = append(order, "target") }
	f := mutationAuditTestFlags()
	f.Yes = true
	auditRoot := t.TempDir()
	prepareMutationAuditTestParent(t, auditRoot)
	f.mutationAuditPath = filepath.Join(auditRoot, "audit.log")
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			order = append(order, record.Phase)
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x61}, 16)),
	}
	if err := applyFlagWrites(context.Background(), f, backend, cfgovctx.Context{}, plan, []plannedFlagWrite{write}, safety.R1, ""); err != nil {
		t.Fatalf("applyFlagWrites() error = %v", err)
	}
	if got := strings.Join(order, ","); got != "intent,target,outcome" {
		t.Fatalf("mutation order = %q, want intent,target,outcome", got)
	}
}

func TestApplyFlagWritesPreviewAndDenialEmitNoMutationIntent(t *testing.T) {
	newWrite := func(t *testing.T) (*flagWriteBackend, plannedFlagWrite, flagWritePlan) {
		t.Helper()
		backend := newFlagWriteBackend([]byte(`[{"key":"checkout","enabled":true}]`))
		current := flagSetResult{
			App:      "app",
			Count:    1,
			Key:      "FEATURE_FLAG_GROUP/app-flags",
			Revision: "rev1",
			SHA256:   sha256Bytes(backend.content),
			Flags:    []flag.FeatureFlag{{Key: "checkout", Enabled: true}},
		}
		write, plan, err := plannedFlagSetWrite(
			backend,
			"app",
			safety.R1,
			"update",
			current,
			[]flag.FeatureFlag{{Key: "checkout", Enabled: false}},
		)
		if err != nil {
			t.Fatalf("plannedFlagSetWrite() error = %v", err)
		}
		return backend, write, plan
	}
	for _, test := range []struct {
		name    string
		prepare func(*cliFlags)
	}{
		{name: "preview", prepare: func(f *cliFlags) { f.Plan = true }},
		{name: "denial", prepare: func(f *cliFlags) {
			f.NonInter = true
			f.NoBackup = true
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend, write, plan := newWrite(t)
			appendCalls := 0
			f := mutationAuditTestFlags()
			auditRoot := t.TempDir()
			prepareMutationAuditTestParent(t, auditRoot)
			f.mutationAuditPath = filepath.Join(auditRoot, "audit.log")
			f.mutationAudit = &mutationAuditRuntime{
				appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
					appendCalls++
					return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
				},
				now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
				random: bytes.NewReader(bytes.Repeat([]byte{0x71}, 16)),
			}
			test.prepare(f)
			err := applyFlagWrites(context.Background(), f, backend, cfgovctx.Context{}, plan, []plannedFlagWrite{write}, safety.R1, "")
			if test.name == "preview" && err != nil {
				t.Fatalf("preview applyFlagWrites() error = %v", err)
			}
			if test.name == "denial" && apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
				t.Fatalf("denial applyFlagWrites() error = %v, want authorization required", err)
			}
			if appendCalls != 0 {
				t.Fatalf("mutation audit append calls = %d, want 0", appendCalls)
			}
			if backend.puts != 0 || backend.deletes != 0 {
				t.Fatalf("backend calls = put %d delete %d, want zero", backend.puts, backend.deletes)
			}
		})
	}
}

func TestApplyFlagWritesSkipsIdempotentWrite(t *testing.T) {
	payload := []byte(`[{"key":"checkout","enabled":true}]`)
	backend := newFlagWriteBackend(payload)
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
	content     []byte
	revision    string
	supportsCAS bool
	puts        int
	deletes     int
	onPut       func()
	lastPut     cfgov.PutRequest
}

func newFlagWriteBackend(content []byte) *flagWriteBackend {
	return &flagWriteBackend{content: append([]byte(nil), content...), revision: "rev1", supportsCAS: true}
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
	if req.RequireAbsent && b.content != nil {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config already exists", nil)
	}
	if b.onPut != nil {
		b.onPut()
	}
	b.puts++
	b.lastPut = req
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
	return cfgov.Capabilities{Backend: "fake", SupportsFlags: true, SupportsCAS: b.supportsCAS}
}
