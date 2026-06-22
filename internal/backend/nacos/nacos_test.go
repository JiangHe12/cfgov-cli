package nacos

import (
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/api"
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
