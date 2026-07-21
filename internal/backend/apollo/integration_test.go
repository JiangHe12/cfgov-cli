//go:build integration

package apollo

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestIntegrationApolloOpenAPIConfigLifecycleAndFailClosedPreconditions(t *testing.T) {
	addr := requiredIntegrationEnv(t, "CFGOV_IT_APOLLO_ADDR")
	token := requiredIntegrationEnv(t, "CFGOV_IT_APOLLO_TOKEN")
	appID := requiredIntegrationEnv(t, "CFGOV_IT_APOLLO_APP_ID")
	env := requiredIntegrationEnv(t, "CFGOV_IT_APOLLO_ENV")
	cluster := requiredIntegrationEnv(t, "CFGOV_IT_APOLLO_CLUSTER")
	namespace := requiredIntegrationEnv(t, "CFGOV_IT_APOLLO_NAMESPACE")

	backend, err := New(Options{
		Server:    addr,
		Token:     token,
		AppID:     appID,
		Env:       env,
		Cluster:   cluster,
		Namespace: namespace,
		Operator:  "apollo",
		Reason:    "real OpenAPI integration test",
		Timeout:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()
	if err := backend.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	coord := cfgov.Coordinate{Namespace: namespace, Key: integrationName(t) + ".value"}
	t.Cleanup(func() {
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: coord})
	})

	first, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: coord, Content: []byte("first")})
	if err != nil {
		t.Fatalf("Put(create) error = %v", err)
	}
	if string(first.Content) != "first" || first.Revision == "" {
		t.Fatalf("Put(create) = %#v, want first with revision", first)
	}
	assertApolloContent(t, ctx, backend, coord, "first")

	items, err := backend.List(ctx, cfgov.ListOptions{Namespace: namespace, Query: coord.Key, Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 || items[0].Coordinate != coord {
		t.Fatalf("List() = %#v, want only %#v", items, coord)
	}

	updated, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: coord, Content: []byte("updated")})
	if err != nil {
		t.Fatalf("Put(update) error = %v", err)
	}
	if string(updated.Content) != "updated" || updated.Revision == "" {
		t.Fatalf("Put(update) = %#v, want updated with revision", updated)
	}

	for name, request := range map[string]cfgov.PutRequest{
		"require absent":    {Coordinate: coord, Content: []byte("replacement"), RequireAbsent: true},
		"expected revision": {Coordinate: coord, Content: []byte("replacement"), ExpectedRevision: updated.Revision},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := backend.Put(ctx, request); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
				t.Fatalf("Put() error = %v, want not implemented", err)
			}
		})
	}
	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: coord, ExpectedRevision: updated.Revision}); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("Delete(expected revision) error = %v, want not implemented", err)
	}
	assertApolloContent(t, ctx, backend, coord, "updated")

	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := backend.Get(ctx, coord); apperrors.AsAppError(err).Code != apperrors.CodeResourceNotFound {
		t.Fatalf("Get(after delete) error = %v, want not found", err)
	}
}

func requiredIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value != "" {
		return value
	}
	if os.Getenv("CFGOV_IT_REQUIRED") == "1" {
		t.Fatalf("%s is required when CFGOV_IT_REQUIRED=1", name)
	}
	t.Skipf("set %s to run", name)
	return ""
}

func assertApolloContent(t *testing.T, ctx context.Context, backend *Backend, coord cfgov.Coordinate, want string) {
	t.Helper()
	got, err := backend.Get(ctx, coord)
	if err != nil {
		t.Fatalf("Get(%#v) error = %v", coord, err)
	}
	if string(got.Content) != want {
		t.Fatalf("Get(%#v) content = %q, want %q", coord, got.Content, want)
	}
}

func integrationName(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", "_", "-", " ", "-").Replace(strings.ToLower(t.Name()))
	return "it-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + name
}
