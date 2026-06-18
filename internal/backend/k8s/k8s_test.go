package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

func TestValidateKeyFailClosed(t *testing.T) {
	t.Parallel()
	valid := []string{
		"configmap/app/application.yaml",
		"secret/s/db-password",
	}
	for _, key := range valid {
		t.Run("valid "+key, func(t *testing.T) {
			t.Parallel()
			if err := newTestBackend().ValidateKey(key); err != nil {
				t.Fatalf("ValidateKey(%q) error = %v", key, err)
			}
		})
	}

	invalid := []string{
		"configmap/app",
		"configmap/app/key/extra",
		"service/app/key",
		"ConfigMap/app/key",
		"configmap/-bad/key",
		"configmap/bad_/key",
		"configmap/app/bad/key",
		"configmap/app/bad key",
		"configmap/app/.",
		"configmap/app/..",
		"configmap//key",
		"./app/key",
		"../app/key",
		"configmap/app/key\nx",
		`configmap/app/bad\key`,
	}
	for _, key := range invalid {
		t.Run("invalid "+strings.ReplaceAll(key, "\n", "\\n"), func(t *testing.T) {
			t.Parallel()
			if err := newTestBackend().ValidateKey(key); err == nil {
				t.Fatalf("ValidateKey(%q) error = nil, want fail-closed error", key)
			}
		})
	}
}

func TestSecretRoundTripStoresSerializedBase64AndReadsPlaintext(t *testing.T) {
	t.Parallel()
	backend := newTestBackend()
	content := []byte("super-secret-value")
	blob, err := backend.Put(context.Background(), cfgov.PutRequest{
		Coordinate: cfgov.Coordinate{Namespace: "default", Key: "secret/app/db-password"},
		Content:    content,
	})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if string(blob.Content) != string(content) {
		t.Fatalf("Put() content = %q, want plaintext", blob.Content)
	}
	secret, err := backend.client.CoreV1().Secrets("default").Get(context.Background(), "app", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get secret from fake client error = %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(content)
	payload, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	if !bytes.Contains(payload, []byte(encoded)) {
		t.Fatalf("serialized secret does not contain base64 payload %q: %s", encoded, payload)
	}
	if bytes.Contains(payload, content) {
		t.Fatalf("serialized secret leaked plaintext payload: %s", payload)
	}
	got, err := backend.Get(context.Background(), cfgov.Coordinate{Namespace: "default", Key: "secret/app/db-password"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got.Content) != string(content) {
		t.Fatalf("Get() content = %q, want %q", got.Content, content)
	}
}

func TestListFlattensConfigMapsAndSecretsWithPrefix(t *testing.T) {
	t.Parallel()
	backend := newTestBackendWithObjects(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", ResourceVersion: "11"},
			Data:       map[string]string{"application.yaml": "a", "logging.properties": "b"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default", ResourceVersion: "12"},
			Data:       map[string][]byte{"db-password": []byte("secret")},
		},
	)
	items, err := backend.List(context.Background(), cfgov.ListOptions{Namespace: "default"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	got := map[string]string{}
	for _, item := range items {
		got[item.Coordinate.Key] = item.Type
	}
	want := map[string]string{
		"configmap/app/application.yaml":   "configmap",
		"configmap/app/logging.properties": "configmap",
		"secret/s/db-password":             "secret",
	}
	for key, typ := range want {
		if got[key] != typ {
			t.Fatalf("List() item %q type = %q, want %q; all=%#v", key, got[key], typ, got)
		}
	}
	filtered, err := backend.List(context.Background(), cfgov.ListOptions{Namespace: "default", Prefix: "secret/"})
	if err != nil {
		t.Fatalf("List(prefix) error = %v", err)
	}
	if len(filtered) != 1 || filtered[0].Coordinate.Key != "secret/s/db-password" || filtered[0].Type != "secret" {
		t.Fatalf("List(prefix) = %#v, want one secret item", filtered)
	}
}

func TestCASConflictAndGetMissing(t *testing.T) {
	t.Parallel()
	backend := newTestBackendWithObjects(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", ResourceVersion: "2"},
		Data:       map[string]string{"application.yaml": "old"},
	})
	_, err := backend.Put(context.Background(), cfgov.PutRequest{
		Coordinate:       cfgov.Coordinate{Namespace: "default", Key: "configmap/app/application.yaml"},
		Content:          []byte("new"),
		ExpectedRevision: "1",
	})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("Put() code = %s, want %s (err=%v)", got, apperrors.CodeConflict, err)
	}
	_, err = backend.Get(context.Background(), cfgov.Coordinate{Namespace: "default", Key: "secret/missing/key"})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeResourceNotFound {
		t.Fatalf("Get missing code = %s, want %s (err=%v)", got, apperrors.CodeResourceNotFound, err)
	}
}

func TestPutUpsertsOneDataKeyAndDeletePreservesObject(t *testing.T) {
	t.Parallel()
	backend := newTestBackendWithObjects(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", ResourceVersion: "3"},
			Data:       map[string]string{"keep": "same"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default", ResourceVersion: "4"},
			Data:       map[string][]byte{"keep": []byte("same"), "remove": []byte("gone")},
		},
	)
	if _, err := backend.Put(context.Background(), cfgov.PutRequest{
		Coordinate: cfgov.Coordinate{Namespace: "default", Key: "configmap/app/new-key"},
		Content:    []byte("new"),
	}); err != nil {
		t.Fatalf("Put configmap error = %v", err)
	}
	cm, err := backend.client.CoreV1().ConfigMaps("default").Get(context.Background(), "app", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get configmap error = %v", err)
	}
	if cm.Data["keep"] != "same" || cm.Data["new-key"] != "new" {
		t.Fatalf("configmap data = %#v, want keep + new-key", cm.Data)
	}
	if err := backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: cfgov.Coordinate{Namespace: "default", Key: "secret/s/remove"}}); err != nil {
		t.Fatalf("Delete secret data key error = %v", err)
	}
	secret, err := backend.client.CoreV1().Secrets("default").Get(context.Background(), "s", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("secret object deleted unexpectedly: %v", err)
	}
	if string(secret.Data["keep"]) != "same" {
		t.Fatalf("secret keep key = %q, want same", secret.Data["keep"])
	}
	if _, ok := secret.Data["remove"]; ok {
		t.Fatalf("secret remove key still present: %#v", secret.Data)
	}
}

func TestTraceDoesNotPrintDataValues(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	backend := newTestBackend()
	backend.trace = true
	backend.traceOut = &out
	if _, err := backend.Put(context.Background(), cfgov.PutRequest{
		Coordinate: cfgov.Coordinate{Namespace: "default", Key: "secret/app/db-password"},
		Content:    []byte("super-secret-value"),
	}); err != nil {
		t.Fatalf("Put secret error = %v", err)
	}
	if _, err := backend.Put(context.Background(), cfgov.PutRequest{
		Coordinate: cfgov.Coordinate{Namespace: "default", Key: "configmap/app/application.yaml"},
		Content:    []byte("plain-config-value"),
	}); err != nil {
		t.Fatalf("Put configmap error = %v", err)
	}
	trace := out.String()
	for _, leaked := range []string{"super-secret-value", "plain-config-value"} {
		if strings.Contains(trace, leaked) {
			t.Fatalf("trace leaked data value %q: %s", leaked, trace)
		}
	}
	if !strings.Contains(trace, "value=<redacted:") {
		t.Fatalf("trace did not include redacted value marker: %s", trace)
	}
}

func TestRuleCoordinateDerivesConfigMapRuleKeys(t *testing.T) {
	t.Parallel()
	backend := newTestBackend()
	tests := map[rule.Type]string{
		rule.TypeFlow:      "configmap/demo-flow-rules/rules.json",
		rule.TypeDegrade:   "configmap/demo-degrade-rules/rules.json",
		rule.TypeSystem:    "configmap/demo-system-rules/rules.json",
		rule.TypeAuthority: "configmap/demo-authority-rules/rules.json",
		rule.TypeParam:     "configmap/demo-param-rules/rules.json",
	}
	for ruleType, wantKey := range tests {
		t.Run(string(ruleType), func(t *testing.T) {
			t.Parallel()
			coord, err := backend.RuleCoordinate("demo", string(ruleType))
			if err != nil {
				t.Fatalf("RuleCoordinate() error = %v", err)
			}
			if coord.Namespace != "default" || coord.Key != wantKey {
				t.Fatalf("RuleCoordinate() = %#v, want default/%s", coord, wantKey)
			}
		})
	}
}

func TestRuleCoordinateRejectsInvalidAppBeforeAPI(t *testing.T) {
	t.Parallel()
	tests := []string{"MyApp", "bad/app", "..", "bad\napp"}
	for _, app := range tests {
		t.Run(strings.ReplaceAll(app, "\n", "\\n"), func(t *testing.T) {
			t.Parallel()
			backend := newTestBackend()
			_, err := backend.RuleCoordinate(app, "flow")
			if err == nil {
				t.Fatalf("RuleCoordinate(%q) error = nil, want fail-closed error", app)
			}
			client := backend.client.(*fake.Clientset)
			if actions := client.Actions(); len(actions) != 0 {
				t.Fatalf("RuleCoordinate(%q) made API calls: %#v", app, actions)
			}
		})
	}
}

func TestRuleCoordinatePutGetRoundTrip(t *testing.T) {
	t.Parallel()
	backend := newTestBackend()
	coord, err := backend.RuleCoordinate("demo", "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate() error = %v", err)
	}
	payload := []byte(`[{"resource":"GET:/demo","count":1}]`)
	if _, err := backend.Put(context.Background(), cfgov.PutRequest{Coordinate: coord, Content: payload}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	cm, err := backend.client.CoreV1().ConfigMaps("default").Get(context.Background(), "demo-flow-rules", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get ConfigMap error = %v", err)
	}
	if cm.Data[ruleDataKey] != string(payload) {
		t.Fatalf("ConfigMap %s = %q, want %q", ruleDataKey, cm.Data[ruleDataKey], payload)
	}
	blob, err := backend.Get(context.Background(), coord)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(blob.Content) != string(payload) {
		t.Fatalf("Get() content = %q, want %q", blob.Content, payload)
	}
}

func newTestBackend() *Backend {
	return newTestBackendWithObjects()
}

func newTestBackendWithObjects(objects ...runtime.Object) *Backend {
	backend, err := New(Options{Namespace: "default", client: fake.NewSimpleClientset(objects...)})
	if err != nil {
		panic(err)
	}
	return backend
}
