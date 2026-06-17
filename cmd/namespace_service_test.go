package cmd

import (
	"context"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestNamespaceDeleteUnprotectedDoesNotRequireAllowFlag(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"

	if err := authorizeNamespaceDelete(f, meta); err != nil {
		t.Fatalf("authorize unprotected namespace delete error = %v", err)
	}
}

func TestNamespaceDeleteProtectedEscalatesToR3WithSameAllowFlag(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	meta.Protected = true
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"

	err := authorizeNamespaceDelete(f, meta)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}

	f.AllowSvcDereg = true
	if err := authorizeNamespaceDelete(f, meta); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("cross allow flag error = %v, want authorization required", err)
	}

	f.AllowSvcDereg = false
	f.AllowNSDel = true
	if err := authorizeNamespaceDelete(f, meta); err != nil {
		t.Fatalf("authorize with namespace allow flag error = %v", err)
	}
}

func TestServiceDeregisterUnprotectedDoesNotRequireAllowFlag(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"

	if err := authorizeServiceDeregister(f, meta); err != nil {
		t.Fatalf("authorize unprotected service deregister error = %v", err)
	}
}

func TestServiceDeregisterProtectedEscalatesToR3WithSameAllowFlag(t *testing.T) {
	t.Parallel()
	meta := cfgovctx.Context{}
	meta.Protected = true
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"

	err := authorizeServiceDeregister(f, meta)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}

	f.AllowNSDel = true
	if err := authorizeServiceDeregister(f, meta); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("cross allow flag error = %v, want authorization required", err)
	}

	f.AllowNSDel = false
	f.AllowSvcDereg = true
	if err := authorizeServiceDeregister(f, meta); err != nil {
		t.Fatalf("authorize with service allow flag error = %v", err)
	}
}

func TestNamespaceAndServiceUnsupportedBackendFailClosed(t *testing.T) {
	t.Parallel()
	backend := fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}

	if _, err := namespaceManager(backend); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("namespaceManager error = %v, want not implemented", err)
	}
	if _, err := serviceRegistry(backend); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("serviceRegistry error = %v, want not implemented", err)
	}
}

func TestNamespaceDeletePlanCountsConfigs(t *testing.T) {
	t.Parallel()
	manager := fakeNamespaceManager{configCount: 3}
	count, err := manager.NamespaceConfigCount(t.Context(), "prod")
	if err != nil {
		t.Fatalf("NamespaceConfigCount() error = %v", err)
	}
	plan := namespacePlan{ResourceType: "namespace", Action: "delete", ID: "prod", Risk: safety.R2, ConfigCount: count}
	if plan.ConfigCount != 3 {
		t.Fatalf("configCount = %d, want 3", plan.ConfigCount)
	}
}

type fakeNamespaceManager struct {
	configCount int
}

var _ cfgov.NamespaceManager = (*fakeNamespaceManager)(nil)

func (f fakeNamespaceManager) ListNamespaces(context.Context) ([]cfgov.NamespaceItem, error) {
	return nil, nil
}

func (f fakeNamespaceManager) CreateNamespace(context.Context, string, string, string) error {
	return nil
}

func (f fakeNamespaceManager) UpdateNamespace(context.Context, string, string, string) error {
	return nil
}

func (f fakeNamespaceManager) DeleteNamespace(context.Context, string) error {
	return nil
}

func (f fakeNamespaceManager) NamespaceConfigCount(context.Context, string) (int, error) {
	return f.configCount, nil
}
