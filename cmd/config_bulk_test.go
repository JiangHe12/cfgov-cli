package cmd

import (
	"context"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type fakeConfigBackend struct {
	namespace string
	blobs     map[string][]byte
}

func (f fakeConfigBackend) Get(_ context.Context, coord cfgov.Coordinate) (cfgov.Blob, error) {
	content, ok := f.blobs[coord.Key]
	if !ok {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeResourceNotFound, "not found", nil)
	}
	return cfgov.Blob{Coordinate: coord, Content: content, Revision: sha256Bytes(content)}, nil
}

func (f fakeConfigBackend) ValidateKey(key string) error {
	if key == "" || key == ".." {
		return apperrors.New(apperrors.CodeValidationFailed, "invalid key", nil)
	}
	return nil
}

func (f fakeConfigBackend) Put(context.Context, cfgov.PutRequest) (cfgov.Blob, error) {
	return cfgov.Blob{}, nil
}

func (f fakeConfigBackend) Delete(context.Context, cfgov.DeleteRequest) error { return nil }

func (f fakeConfigBackend) List(context.Context, cfgov.ListOptions) ([]cfgov.ListItem, error) {
	items := make([]cfgov.ListItem, 0, len(f.blobs))
	for key, content := range f.blobs {
		items = append(items, cfgov.ListItem{Coordinate: cfgov.Coordinate{Namespace: f.namespace, Key: key}, Revision: sha256Bytes(content)})
	}
	return items, nil
}

func (f fakeConfigBackend) History(context.Context, cfgov.Coordinate, cfgov.HistoryOptions) ([]cfgov.HistoryItem, int, error) {
	return nil, 0, nil
}

func (f fakeConfigBackend) Watch(context.Context, cfgov.Coordinate, string, cfgov.WatchOptions) (cfgov.WatchEvent, error) {
	return cfgov.WatchEvent{}, nil
}

func (f fakeConfigBackend) CurrentRevision(ctx context.Context, coord cfgov.Coordinate) (string, error) {
	blob, err := f.Get(ctx, coord)
	return blob.Revision, err
}

func (f fakeConfigBackend) Ping(context.Context) error { return nil }

func (f fakeConfigBackend) Describe() cfgov.Description {
	return cfgov.Description{Backend: "fake", Namespace: f.namespace}
}

func (f fakeConfigBackend) Capabilities() cfgov.Capabilities { return cfgov.Capabilities{} }

func TestReconcilePrunePlanIsR3(t *testing.T) {
	t.Parallel()
	backend := fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{
		"app.yaml":    []byte("enabled: true\n"),
		"orphan.yaml": []byte("old\n"),
	}}
	locals := []localConfig{{Key: "app.yaml", Content: []byte("enabled: false\n"), Type: "yaml"}}
	plan, err := buildReconcilePlan(context.Background(), backend, "ns", locals, reconcilePlanOptions{
		Prune:       true,
		PruneScopes: []string{"ns"},
	})
	if err != nil {
		t.Fatalf("buildReconcilePlan() error = %v", err)
	}
	if plan.Risk != safety.R3 {
		t.Fatalf("risk = %v, want R3", plan.Risk)
	}
	if len(plan.Prune) != 1 || plan.Prune[0].Key != "orphan.yaml" {
		t.Fatalf("prune = %#v, want orphan.yaml", plan.Prune)
	}
}

func TestImportPlanSkipExistingAndOverwriteAreDistinct(t *testing.T) {
	t.Parallel()
	backend := fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{
		"app.yaml": []byte("old\n"),
	}}
	locals := []localConfig{{Key: "app.yaml", Content: []byte("new\n"), Type: "yaml"}}
	plan, err := buildUpsertPlan(context.Background(), backend, "ns", locals, upsertPlanOptions{Action: "import", SkipExisting: true})
	if err != nil {
		t.Fatalf("buildUpsertPlan skip error = %v", err)
	}
	if len(plan.Skip) != 1 || len(plan.Update) != 0 || len(plan.Conflict) != 0 {
		t.Fatalf("skip plan = %#v", plan)
	}
	plan, err = buildUpsertPlan(context.Background(), backend, "ns", locals, upsertPlanOptions{Action: "import", Overwrite: true})
	if err != nil {
		t.Fatalf("buildUpsertPlan overwrite error = %v", err)
	}
	if len(plan.Update) != 1 || len(plan.Skip) != 0 || len(plan.Conflict) != 0 {
		t.Fatalf("overwrite plan = %#v", plan)
	}
	plan, err = buildUpsertPlan(context.Background(), backend, "ns", locals, upsertPlanOptions{Action: "import"})
	if err != nil {
		t.Fatalf("buildUpsertPlan conflict error = %v", err)
	}
	if len(plan.Conflict) != 1 || len(plan.Update) != 0 {
		t.Fatalf("conflict plan = %#v", plan)
	}
}

func TestConfigPushStrictModes(t *testing.T) {
	t.Parallel()
	if err := validateConfigPushMode(true, false, true); apperrors.AsAppError(err).Code != apperrors.CodeResourceAlreadyExists {
		t.Fatalf("create-only existing error = %v, want already exists", err)
	}
	if err := validateConfigPushMode(false, true, false); apperrors.AsAppError(err).Code != apperrors.CodeResourceNotFound {
		t.Fatalf("update-only missing error = %v, want not found", err)
	}
	if err := validateConfigPushMode(false, false, true); err != nil {
		t.Fatalf("default upsert with existing error = %v", err)
	}
	if err := validateConfigPushMode(false, false, false); err != nil {
		t.Fatalf("default upsert with missing error = %v", err)
	}
	if err := validateConfigPushMode(true, false, false); err != nil {
		t.Fatalf("create-only missing error = %v", err)
	}
	if err := validateConfigPushMode(false, true, true); err != nil {
		t.Fatalf("update-only existing error = %v", err)
	}
}

func TestPruneScopeRequiresExplicitScopeWhenPruning(t *testing.T) {
	t.Parallel()
	_, err := parsePruneScopes(nil, "ns", true)
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
	scopes, err := parsePruneScopes([]string{"ns/DEFAULT_GROUP"}, "ns", true)
	if err != nil {
		t.Fatalf("parsePruneScopes error = %v", err)
	}
	if !pruneScopeContains(scopes, "ns", "app.yaml") || pruneScopeContains(scopes, "other", "app.yaml") {
		t.Fatalf("scope containment mismatch: %#v", scopes)
	}
}

func TestReconcilePruneRequiresAllowFlag(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"
	err := authorize(f, safety.R3, meta, allowProductionPrune)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}
	f.AllowPrune = true
	if err := authorize(f, safety.R3, meta, allowProductionPrune); err != nil {
		t.Fatalf("authorize with allow prune error = %v", err)
	}
}

func TestProtectedReconcileWithoutPruneDoesNotRequirePruneAllowFlag(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	meta.Protected = true
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"
	if err := authorizeReconcile(f, safety.R2, meta, ""); err != nil {
		t.Fatalf("authorize protected reconcile without prune error = %v", err)
	}
}

func TestImportProtectedR1EscalatesToTicketRequirement(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	meta.Protected = true
	f := newDefaultFlags()
	f.Yes = true
	err := authorize(f, safety.R1, meta, "")
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}
	f.Ticket = "OPS-1"
	if err := authorize(f, safety.R1, meta, ""); err != nil {
		t.Fatalf("authorize protected import style write error = %v", err)
	}
}

func TestPromoteRollbackSingleWriteProtectedNeedsTicket(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	meta.Protected = true
	f := newDefaultFlags()
	f.Yes = true
	err := authorize(f, safety.R1, meta, "")
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}
}
