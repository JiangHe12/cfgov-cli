//go:build integration

package etcd

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

func TestIntegrationEtcdConfigCASListWatchAndRules(t *testing.T) {
	endpoints := os.Getenv("CFGOV_IT_ETCD_ENDPOINTS")
	if endpoints == "" {
		t.Skip("set CFGOV_IT_ETCD_ENDPOINTS to run")
	}
	ctx := context.Background()
	namespace := integrationName(t)
	ruleNamespace := namespace + "-rules"
	backend, err := New(Options{Endpoints: endpoints, Namespace: namespace, RuleNamespace: ruleNamespace})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	coord := cfgov.Coordinate{Namespace: namespace, Key: "app.yaml"}
	sibling, err := New(Options{Endpoints: endpoints, Namespace: namespace + "-other"})
	if err != nil {
		t.Fatalf("New(sibling) error = %v", err)
	}
	siblingCoord := cfgov.Coordinate{Namespace: namespace + "-other", Key: "app.yaml"}
	ruleCoord, err := backend.RuleCoordinate("demo-"+namespace, "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate() error = %v", err)
	}
	t.Cleanup(func() {
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: coord})
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: ruleCoord})
		_ = sibling.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: siblingCoord})
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
	ruleBlob, err := backend.Get(ctx, ruleCoord)
	if err != nil {
		t.Fatalf("Get(rule) error = %v", err)
	}
	if len(ruleBlob.Content) == 0 || ruleBlob.Revision == "" {
		t.Fatalf("rule blob = %#v, want content and revision", ruleBlob)
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
