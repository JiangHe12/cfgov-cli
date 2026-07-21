//go:build integration

package nacos

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/opskit-core/v2/apperrors"
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
	awaitNacosContent(t, ctx, backend, configCoord, []byte("name: demo\n"), "config")
	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: configCoord}); err != nil {
		t.Fatalf("Delete(config) error = %v", err)
	}
	awaitNacosNotFound(t, ctx, backend, configCoord, "deleted config")

	payload := []byte(`[{"resource":"GET:/demo","count":1}]`)
	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: ruleCoord, Content: payload, ContentType: "json"}); err != nil {
		t.Fatalf("Put(rule) error = %v", err)
	}
	awaitNacosContent(t, ctx, backend, ruleCoord, payload, "rule")
	key, err := cfgov.ParseNacosKey(ruleCoord.Key)
	if err != nil {
		t.Fatalf("ParseNacosKey(rule) error = %v", err)
	}
	if key.Group != "SENTINEL_GROUP" {
		t.Fatalf("rule group = %q, want SENTINEL_GROUP", key.Group)
	}
}

func awaitNacosContent(t *testing.T, ctx context.Context, backend *Backend, coord cfgov.Coordinate, want []byte, label string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastContent []byte
	var lastErr error
	for {
		got, err := backend.Get(ctx, coord)
		if err == nil {
			lastErr = nil
			lastContent = got.Content
			if bytes.Equal(got.Content, want) {
				return
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				t.Fatalf("Get(%s) error = %v, want content %q", label, lastErr, want)
			}
			t.Fatalf("Get(%s) content = %q, want %q", label, lastContent, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func awaitNacosNotFound(t *testing.T, ctx context.Context, backend *Backend, coord cfgov.Coordinate, label string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastContent []byte
	var lastErr error
	for {
		got, err := backend.Get(ctx, coord)
		if err != nil {
			lastErr = err
			if apperrors.AsAppError(err).Code == apperrors.CodeResourceNotFound {
				return
			}
		} else {
			lastErr = nil
			lastContent = got.Content
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				t.Fatalf("Get(%s) error = %v, want not found", label, lastErr)
			}
			t.Fatalf("Get(%s) content = %q, want not found", label, lastContent)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func integrationName(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", "_", "-", " ", "-").Replace(strings.ToLower(t.Name()))
	return "it-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + name
}
