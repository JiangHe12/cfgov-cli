//go:build integration

package consul

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	capi "github.com/hashicorp/consul/api"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestIntegrationConsulConfigCASListWatchRulesFlagsAndHealth(t *testing.T) {
	addr := os.Getenv("CFGOV_IT_CONSUL_ADDR")
	if addr == "" {
		if os.Getenv("CFGOV_IT_REQUIRED") == "1" {
			t.Fatal("CFGOV_IT_CONSUL_ADDR is required when CFGOV_IT_REQUIRED=1")
		}
		t.Skip("set CFGOV_IT_CONSUL_ADDR to run")
	}
	ctx := context.Background()
	namespace := integrationName(t)
	backend, err := New(Options{Server: addr, Namespace: namespace})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	coord := cfgov.Coordinate{Namespace: namespace, Key: "app.yaml"}
	createOnlyCoord := cfgov.Coordinate{Namespace: namespace, Key: "create-only.yaml"}
	deleteCASCoord := cfgov.Coordinate{Namespace: namespace, Key: "delete-cas.yaml"}
	sibling, err := New(Options{Server: addr, Namespace: namespace + "-other"})
	if err != nil {
		t.Fatalf("New(sibling) error = %v", err)
	}
	siblingCoord := cfgov.Coordinate{Namespace: namespace + "-other", Key: "app.yaml"}
	ruleCoord, err := backend.RuleCoordinate("demo-"+namespace, "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate() error = %v", err)
	}
	flagCoord, err := backend.FlagCoordinate("demo-" + namespace)
	if err != nil {
		t.Fatalf("FlagCoordinate() error = %v", err)
	}
	service := "svc-" + namespace
	ip := "127.0.0.1"
	port := 18080
	t.Cleanup(func() {
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: coord})
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: createOnlyCoord})
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: deleteCASCoord})
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: ruleCoord})
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: flagCoord})
		_ = sibling.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: siblingCoord})
		if backend.agent != nil {
			_ = backend.agent.ServiceDeregisterOpts(consulServiceID(service, ip, port), backend.queryOptions(context.Background()))
		}
	})

	first, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: coord, Content: []byte("v1")})
	if err != nil {
		t.Fatalf("Put(v1) error = %v", err)
	}
	if string(first.Content) != "v1" || first.Revision == "" {
		t.Fatalf("Put(v1) = %#v, want bytes and non-empty revision", first)
	}
	got, err := backend.Get(ctx, coord)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got.Content) != "v1" {
		t.Fatalf("Get() content = %q, want v1", got.Content)
	}
	second, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: coord, Content: []byte("v2"), ExpectedRevision: first.Revision})
	if err != nil {
		t.Fatalf("Put(v2 correct rev) error = %v", err)
	}
	_, err = backend.Put(ctx, cfgov.PutRequest{Coordinate: coord, Content: []byte("stale"), ExpectedRevision: first.Revision})
	if code := apperrors.AsAppError(err).Code; code != apperrors.CodeConflict {
		t.Fatalf("Put(stale) code = %s, want %s (err=%v)", code, apperrors.CodeConflict, err)
	}

	createdOnly, err := backend.Put(ctx, cfgov.PutRequest{
		Coordinate:    createOnlyCoord,
		Content:       []byte("first"),
		RequireAbsent: true,
	})
	if err != nil {
		t.Fatalf("Put(require absent) error = %v", err)
	}
	if string(createdOnly.Content) != "first" || createdOnly.Revision == "" {
		t.Fatalf("Put(require absent) = %#v, want first with revision", createdOnly)
	}
	_, err = backend.Put(ctx, cfgov.PutRequest{
		Coordinate:    createOnlyCoord,
		Content:       []byte("replacement"),
		RequireAbsent: true,
	})
	if code := apperrors.AsAppError(err).Code; code != apperrors.CodeConflict {
		t.Fatalf("Put(require absent existing) code = %s, want %s (err=%v)", code, apperrors.CodeConflict, err)
	}
	assertContent(t, ctx, backend, createOnlyCoord, "first")

	deleteCASFirst, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: deleteCASCoord, Content: []byte("delete-me-v1")})
	if err != nil {
		t.Fatalf("Put(delete CAS fixture) error = %v", err)
	}
	deleteCASCurrent, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: deleteCASCoord, Content: []byte("delete-me-v2"), ExpectedRevision: deleteCASFirst.Revision})
	if err != nil {
		t.Fatalf("Put(delete CAS fixture update) error = %v", err)
	}
	if deleteCASFirst.Revision == "" || deleteCASCurrent.Revision == "" || deleteCASCurrent.Revision == deleteCASFirst.Revision {
		t.Fatalf("delete CAS revisions = %q -> %q, want distinct non-empty revisions", deleteCASFirst.Revision, deleteCASCurrent.Revision)
	}
	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: deleteCASCoord, ExpectedRevision: deleteCASFirst.Revision}); apperrors.AsAppError(err).Code != apperrors.CodeConflict {
		t.Fatalf("Delete(stale revision) error = %v, want conflict", err)
	}
	assertContent(t, ctx, backend, deleteCASCoord, "delete-me-v2")
	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: deleteCASCoord, ExpectedRevision: deleteCASCurrent.Revision}); err != nil {
		t.Fatalf("Delete(current revision) error = %v", err)
	}
	if _, err := backend.Get(ctx, deleteCASCoord); apperrors.AsAppError(err).Code != apperrors.CodeResourceNotFound {
		t.Fatalf("Get(after delete CAS) error = %v, want not found", err)
	}

	if _, err := sibling.Put(ctx, cfgov.PutRequest{Coordinate: siblingCoord, Content: []byte("sibling")}); err != nil {
		t.Fatalf("Put(sibling) error = %v", err)
	}
	items, err := backend.List(ctx, cfgov.ListOptions{Namespace: namespace, Limit: 100})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if !containsCoord(items, coord) {
		t.Fatalf("List() missing own coord: %#v", items)
	}
	if containsCoord(items, siblingCoord) {
		t.Fatalf("List() leaked sibling namespace coord: %#v", items)
	}

	watchDone := make(chan error, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, putErr := backend.Put(context.Background(), cfgov.PutRequest{Coordinate: coord, Content: []byte("v3"), ExpectedRevision: second.Revision})
		watchDone <- putErr
	}()
	event, err := backend.Watch(ctx, coord, second.Revision, cfgov.WatchOptions{LongPoll: 3 * time.Second})
	if err != nil {
		t.Fatalf("Watch(change) error = %v", err)
	}
	if putErr := <-watchDone; putErr != nil {
		t.Fatalf("watch trigger Put() error = %v", putErr)
	}
	if !event.Changed || event.Revision == "" || event.Revision == second.Revision {
		t.Fatalf("Watch(change) = %#v, want changed with new revision", event)
	}
	unchanged, err := backend.Watch(ctx, coord, event.Revision, cfgov.WatchOptions{LongPoll: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("Watch(timeout) error = %v", err)
	}
	if unchanged.Changed || unchanged.Revision != event.Revision {
		t.Fatalf("Watch(timeout) = %#v, want unchanged revision %q", unchanged, event.Revision)
	}

	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: ruleCoord, Content: []byte(`[{"resource":"GET:/demo","count":1}]`)}); err != nil {
		t.Fatalf("Put(rule) error = %v", err)
	}
	if _, err := backend.Get(ctx, ruleCoord); err != nil {
		t.Fatalf("Get(rule) error = %v", err)
	}
	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: flagCoord, Content: []byte(`{"flags":[]}`)}); err != nil {
		t.Fatalf("Put(flag) error = %v", err)
	}
	if _, err := backend.Get(ctx, flagCoord); err != nil {
		t.Fatalf("Get(flag) error = %v", err)
	}

	agent, ok := backend.agent.(interface {
		ServiceRegisterOpts(*capi.AgentServiceRegistration, capi.ServiceRegisterOpts) error
		ServiceDeregisterOpts(string, *capi.QueryOptions) error
		UpdateTTL(string, string, string) error
	})
	if !ok {
		t.Fatalf("consul agent does not support service registration and UpdateTTL")
	}
	serviceID := consulServiceID(service, ip, port)
	checkID := "service:" + serviceID
	if err := agent.ServiceRegisterOpts(&capi.AgentServiceRegistration{
		ID:      serviceID,
		Name:    service,
		Address: ip,
		Port:    port,
		Check:   &capi.AgentServiceCheck{CheckID: checkID, TTL: "30s", Status: capi.HealthPassing},
	}, capi.ServiceRegisterOpts{}.WithContext(ctx)); err != nil {
		t.Fatalf("ServiceRegisterOpts() error = %v", err)
	}
	if err := agent.UpdateTTL(checkID, "passing", capi.HealthPassing); err != nil {
		t.Fatalf("UpdateTTL(passing) error = %v", err)
	}
	assertConsulHealth(t, ctx, backend, service, true)
	if err := agent.UpdateTTL(checkID, "critical", capi.HealthCritical); err != nil {
		t.Fatalf("UpdateTTL(critical) error = %v", err)
	}
	assertConsulHealth(t, ctx, backend, service, false)
}

func assertContent(t *testing.T, ctx context.Context, backend *Backend, coord cfgov.Coordinate, want string) {
	t.Helper()
	got, err := backend.Get(ctx, coord)
	if err != nil {
		t.Fatalf("Get(%#v) error = %v", coord, err)
	}
	if string(got.Content) != want {
		t.Fatalf("Get(%#v) content = %q, want %q", coord, got.Content, want)
	}
}

func assertConsulHealth(t *testing.T, ctx context.Context, backend *Backend, service string, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		items, err := backend.ListInstances(ctx, service, "")
		if err != nil {
			t.Fatalf("ListInstances(%q) error = %v", service, err)
		}
		if len(items) > 0 && items[0].Healthy == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ListInstances(%q) = %#v, want Healthy=%v", service, items, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func integrationName(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", "_", "-", " ", "-").Replace(strings.ToLower(t.Name()))
	return "it-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + name
}

func containsCoord(items []cfgov.ListItem, coord cfgov.Coordinate) bool {
	for _, item := range items {
		if item.Coordinate == coord {
			return true
		}
	}
	return false
}
