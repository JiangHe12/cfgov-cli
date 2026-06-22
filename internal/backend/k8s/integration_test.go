//go:build integration

package k8s

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestIntegrationK8sRealAPIServerConfigSecretCASWatchRulesFlags(t *testing.T) {
	kubeconfig := os.Getenv("CFGOV_IT_K8S_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("set CFGOV_IT_K8S_KUBECONFIG to run")
	}
	ctx := context.Background()
	var trace bytes.Buffer
	backend, err := New(Options{
		Kubeconfig: kubeconfig,
		Namespace:  "default",
		Trace:      true,
		TraceOut:   &trace,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	prefix := integrationName(t)
	cmName := prefix + "-cm"
	secretName := prefix + "-secret"
	watchCMName := prefix + "-watch-cm"
	watchSecretName := prefix + "-watch-secret"
	app := "demo-" + prefix
	configCoord := cfgov.Coordinate{Namespace: "default", Key: "configmap/" + cmName + "/application.yaml"}
	configOtherCoord := cfgov.Coordinate{Namespace: "default", Key: "configmap/" + cmName + "/other.yaml"}
	secretCoord := cfgov.Coordinate{Namespace: "default", Key: "secret/" + secretName + "/password"}
	secretOtherCoord := cfgov.Coordinate{Namespace: "default", Key: "secret/" + secretName + "/keep"}
	watchConfigCoord := cfgov.Coordinate{Namespace: "default", Key: "configmap/" + watchCMName + "/application.yaml"}
	watchSecretCoord := cfgov.Coordinate{Namespace: "default", Key: "secret/" + watchSecretName + "/password"}
	ruleCoord, err := backend.RuleCoordinate(app, "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate() error = %v", err)
	}
	flagCoord, err := backend.FlagCoordinate(app)
	if err != nil {
		t.Fatalf("FlagCoordinate() error = %v", err)
	}
	t.Cleanup(func() {
		for _, name := range []string{cmName, watchCMName, app + "-flow-rules", app + "-flags"} {
			deleteConfigMapIfPresent(t, backend, name)
		}
		for _, name := range []string{secretName, watchSecretName} {
			deleteSecretIfPresent(t, backend, name)
		}
	})

	first, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: configCoord, Content: []byte("name: demo\n"), ContentType: "yaml"})
	if err != nil {
		t.Fatalf("Put(config) error = %v", err)
	}
	if first.Revision == "" {
		t.Fatalf("Put(config) revision empty")
	}
	assertBlobContent(t, ctx, backend, configCoord, []byte("name: demo\n"), "config")
	second, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: configCoord, Content: []byte("name: changed\n"), ContentType: "yaml", ExpectedRevision: first.Revision})
	if err != nil {
		t.Fatalf("Put(config expected revision) error = %v", err)
	}
	if second.Revision == "" || second.Revision == first.Revision {
		t.Fatalf("Put(config expected revision) revision = %q, want non-empty revision different from %q", second.Revision, first.Revision)
	}
	_, err = backend.Put(ctx, cfgov.PutRequest{Coordinate: configCoord, Content: []byte("name: stale\n"), ContentType: "yaml", ExpectedRevision: first.Revision})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("Put(config stale revision) code = %s, want %s (err=%v)", got, apperrors.CodeConflict, err)
	}

	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: configOtherCoord, Content: []byte("keep: true\n"), ContentType: "yaml"}); err != nil {
		t.Fatalf("Put(config other key) error = %v", err)
	}
	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: configCoord}); err != nil {
		t.Fatalf("Delete(config data key) error = %v", err)
	}
	cm, err := backend.client.CoreV1().ConfigMaps("default").Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get ConfigMap after data-key delete error = %v", err)
	}
	if _, ok := cm.Data["application.yaml"]; ok {
		t.Fatalf("ConfigMap deleted data key still present: %#v", cm.Data)
	}
	if cm.Data["other.yaml"] != "keep: true\n" {
		t.Fatalf("ConfigMap other data key = %q, want preserved", cm.Data["other.yaml"])
	}

	secretPayload := []byte("k8s-integration-secret-value")
	secretFirst, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: secretCoord, Content: secretPayload})
	if err != nil {
		t.Fatalf("Put(secret) error = %v", err)
	}
	if secretFirst.Revision == "" {
		t.Fatalf("Put(secret) revision empty")
	}
	assertBlobContent(t, ctx, backend, secretCoord, secretPayload, "secret")
	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: secretOtherCoord, Content: []byte("keep-secret")}); err != nil {
		t.Fatalf("Put(secret other key) error = %v", err)
	}
	if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: secretCoord}); err != nil {
		t.Fatalf("Delete(secret data key) error = %v", err)
	}
	secret, err := backend.client.CoreV1().Secrets("default").Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get Secret after data-key delete error = %v", err)
	}
	if _, ok := secret.Data["password"]; ok {
		t.Fatalf("Secret deleted data key still present")
	}
	if string(secret.Data["keep"]) != "keep-secret" {
		t.Fatalf("Secret keep data key = %q, want preserved", secret.Data["keep"])
	}

	watchStart, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: watchConfigCoord, Content: []byte("version: 1\n"), ContentType: "yaml"})
	if err != nil {
		t.Fatalf("Put(watch config initial) error = %v", err)
	}
	watchDone := make(chan error, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, err := backend.Put(context.Background(), cfgov.PutRequest{Coordinate: watchConfigCoord, Content: []byte("version: 2\n"), ContentType: "yaml"})
		watchDone <- err
	}()
	event, err := backend.Watch(ctx, watchConfigCoord, watchStart.Revision, cfgov.WatchOptions{LongPoll: 5 * time.Second})
	if err != nil {
		t.Fatalf("Watch(config) error = %v", err)
	}
	if err := <-watchDone; err != nil {
		t.Fatalf("Put(watch config update) error = %v", err)
	}
	if !event.Changed || event.Revision == "" || event.Revision == watchStart.Revision || event.Coordinate != watchConfigCoord {
		t.Fatalf("Watch(config) = %#v, want changed event with new revision", event)
	}
	unchanged, err := backend.Watch(ctx, watchConfigCoord, event.Revision, cfgov.WatchOptions{LongPoll: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("Watch(config unchanged) error = %v", err)
	}
	if unchanged.Changed || unchanged.Revision != event.Revision || unchanged.Coordinate != watchConfigCoord {
		t.Fatalf("Watch(config unchanged) = %#v, want unchanged original revision", unchanged)
	}

	secretWatchStart, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: watchSecretCoord, Content: []byte("initial-secret")})
	if err != nil {
		t.Fatalf("Put(watch secret initial) error = %v", err)
	}
	secretWatchPayload := []byte("secret-watch-payload-must-not-leak")
	secretWatchDone := make(chan error, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, err := backend.Put(context.Background(), cfgov.PutRequest{Coordinate: watchSecretCoord, Content: secretWatchPayload})
		secretWatchDone <- err
	}()
	secretEvent, err := backend.Watch(ctx, watchSecretCoord, secretWatchStart.Revision, cfgov.WatchOptions{LongPoll: 5 * time.Second})
	if err != nil {
		t.Fatalf("Watch(secret) error = %v", err)
	}
	if err := <-secretWatchDone; err != nil {
		t.Fatalf("Put(watch secret update) error = %v", err)
	}
	if !secretEvent.Changed || secretEvent.Revision == "" || secretEvent.Revision == secretWatchStart.Revision || secretEvent.Coordinate != watchSecretCoord {
		t.Fatalf("Watch(secret) = %#v, want changed event with new revision", secretEvent)
	}
	if bytes.Contains([]byte(fmt.Sprintf("%#v", secretEvent)), secretWatchPayload) {
		t.Fatalf("Watch(secret) event leaked secret payload: %#v", secretEvent)
	}
	if bytes.Contains(trace.Bytes(), secretWatchPayload) {
		t.Fatalf("trace leaked secret payload: %s", trace.String())
	}

	rulePayload := []byte(`[{"resource":"GET:/demo","count":1}]`)
	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: ruleCoord, Content: rulePayload, ContentType: "json"}); err != nil {
		t.Fatalf("Put(rule) error = %v", err)
	}
	assertBlobContent(t, ctx, backend, ruleCoord, rulePayload, "rule")
	flagPayload := []byte(`[{"key":"enabled","enabled":true}]`)
	if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: flagCoord, Content: flagPayload, ContentType: "json"}); err != nil {
		t.Fatalf("Put(flag) error = %v", err)
	}
	assertBlobContent(t, ctx, backend, flagCoord, flagPayload, "flag")
}

func assertBlobContent(t *testing.T, ctx context.Context, backend *Backend, coord cfgov.Coordinate, want []byte, label string) {
	t.Helper()
	got, err := backend.Get(ctx, coord)
	if err != nil {
		t.Fatalf("Get(%s) error = %v", label, err)
	}
	if !bytes.Equal(got.Content, want) {
		t.Fatalf("Get(%s) content = %q, want %q", label, got.Content, want)
	}
	if got.Revision == "" {
		t.Fatalf("Get(%s) revision empty", label)
	}
}

func integrationName(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", "_", "-", " ", "-").Replace(strings.ToLower(t.Name()))
	if len(name) > 18 {
		name = name[:18]
	}
	return "it-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strings.Trim(name, "-")
}

func deleteConfigMapIfPresent(t *testing.T, backend *Backend, name string) {
	t.Helper()
	err := backend.client.CoreV1().ConfigMaps("default").Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		t.Fatalf("cleanup ConfigMap %q error = %v", name, err)
	}
}

func deleteSecretIfPresent(t *testing.T, backend *Backend, name string) {
	t.Helper()
	err := backend.client.CoreV1().Secrets("default").Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		t.Fatalf("cleanup Secret %q error = %v", name, err)
	}
}
