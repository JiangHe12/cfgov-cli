package nacos

import (
	"context"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestFlagCoordinate(t *testing.T) {
	t.Parallel()
	backend := New(api.NewClient("http://nacos.example", "", "", "ns", time.Second), "http://nacos.example")
	coord, err := backend.FlagCoordinate("order-service")
	if err != nil {
		t.Fatalf("FlagCoordinate() error = %v", err)
	}
	if coord.Namespace != "ns" || coord.Key != "FEATURE_FLAG_GROUP/order-service-flags" {
		t.Fatalf("coord = %#v", coord)
	}
}

func TestFlagCoordinateRejectsInjectedApp(t *testing.T) {
	t.Parallel()
	backend := New(api.NewClient("http://nacos.example", "", "", "ns", time.Second), "http://nacos.example")
	tests := []string{"../prod", "bad/app", "bad\\app", "bad\napp"}
	for _, app := range tests {
		t.Run(app, func(t *testing.T) {
			t.Parallel()
			if _, err := backend.FlagCoordinate(app); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
				t.Fatalf("error = %v, want validation failed", err)
			}
		})
	}
}

func TestPublicNamespaceCoordinateMatchesDefaultTenant(t *testing.T) {
	t.Parallel()
	backend := New(api.NewClient("http://nacos.example", "", "", "public", time.Second), "http://nacos.example")
	if backend.Describe().Namespace != "" {
		t.Fatalf("Describe().Namespace = %q, want empty public tenant", backend.Describe().Namespace)
	}
	err := backend.requireNamespace("public")
	if err != nil {
		t.Fatalf("requireNamespace(public) error = %v", err)
	}
	if _, err := backend.List(context.Background(), cfgov.ListOptions{Namespace: "wmc_dev"}); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("List(wmc_dev) error = %v, want usage error", err)
	}
}

func TestCapabilitiesAndRevisionPreconditionsAreHonest(t *testing.T) {
	t.Parallel()
	backend := New(api.NewClient("http://nacos.example", "", "", "ns", time.Second), "http://nacos.example")
	if backend.Capabilities().SupportsCAS {
		t.Fatal("Nacos check-then-write must not be reported as atomic CAS")
	}
	coord := cfgov.Coordinate{Namespace: "ns", Key: "DEFAULT_GROUP/app.yaml"}
	for name, request := range map[string]cfgov.PutRequest{
		"expected revision": {Coordinate: coord, Content: []byte("x"), ExpectedRevision: "stale"},
		"require absent":    {Coordinate: coord, Content: []byte("x"), RequireAbsent: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := backend.Put(context.Background(), request); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
				t.Fatalf("Put() error = %v, want NOT_IMPLEMENTED", err)
			}
		})
	}
	if err := backend.Delete(context.Background(), cfgov.DeleteRequest{
		Coordinate:       coord,
		ExpectedRevision: "stale",
	}); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("Delete() error = %v, want NOT_IMPLEMENTED", err)
	}
}
