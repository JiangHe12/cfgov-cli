//go:build integration

package nacos

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestIntegrationNacosConfigGroupDataIDAndRules(t *testing.T) {
	addr := os.Getenv("CFGOV_IT_NACOS_ADDR")
	if addr == "" {
		t.Skip("set CFGOV_IT_NACOS_ADDR to run")
	}
	ctx := context.Background()
	prefix := integrationName(t)
	backend := New(api.NewClient(addr, "", "", "", 30*time.Second), addr)
	configCoord := cfgov.Coordinate{Key: cfgov.FormatNacosKey("IT_"+prefix, prefix+".yaml")}
	ruleCoord, err := backend.RuleCoordinate("demo-"+prefix, "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate() error = %v", err)
	}
	t.Cleanup(func() {
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: configCoord})
		_ = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: ruleCoord})
	})

	first, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: configCoord, Content: []byte("name: demo\n"), ContentType: "yaml"})
	if err != nil {
		t.Fatalf("Put(config) error = %v", err)
	}
	if first.Revision == "" {
		t.Fatalf("Put(config) revision empty")
	}
	got, err := backend.Get(ctx, configCoord)
	if err != nil {
		t.Fatalf("Get(config) error = %v", err)
	}
	if string(got.Content) != "name: demo\n" {
		t.Fatalf("Get(config) content = %q, want original bytes", got.Content)
	}
	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: configCoord}); err != nil {
		t.Fatalf("Delete(config) error = %v", err)
	}
	if _, err := backend.Get(ctx, configCoord); err == nil {
		t.Fatalf("Get(deleted config) error = nil, want not found")
	}

	payload := []byte(`[{"resource":"GET:/demo","count":1}]`)
	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: ruleCoord, Content: payload, ContentType: "json"}); err != nil {
		t.Fatalf("Put(rule) error = %v", err)
	}
	ruleBlob, err := backend.Get(ctx, ruleCoord)
	if err != nil {
		t.Fatalf("Get(rule) error = %v", err)
	}
	if string(ruleBlob.Content) != string(payload) {
		t.Fatalf("Get(rule) content = %q, want %q", ruleBlob.Content, payload)
	}
	key, err := cfgov.ParseNacosKey(ruleCoord.Key)
	if err != nil {
		t.Fatalf("ParseNacosKey(rule) error = %v", err)
	}
	if key.Group != "SENTINEL_GROUP" {
		t.Fatalf("rule group = %q, want SENTINEL_GROUP", key.Group)
	}
}

func integrationName(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", "_", "-", " ", "-").Replace(strings.ToLower(t.Name()))
	return "it-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + name
}
