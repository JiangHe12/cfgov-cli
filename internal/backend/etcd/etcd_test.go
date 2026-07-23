package etcd

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/grpclog"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestEtcdGRPCLibraryLoggerIsSilent(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
		_ = writer.Close()
		_ = reader.Close()
	}()

	grpclog.Errorf("must not reach stderr: token=library-secret")
	_ = writer.Close()
	os.Stderr = oldStderr
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) != 0 {
		t.Fatalf("gRPC library logger wrote to stderr: %q", output)
	}
}

func TestNewValidatesEtcdOptionsFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts Options
	}{
		{name: "missing endpoints", opts: Options{Namespace: "app"}},
		{name: "bad scheme", opts: Options{Endpoints: "ftp://127.0.0.1:2379", Namespace: "app"}},
		{name: "endpoint credentials", opts: Options{Endpoints: "http://user:pass@127.0.0.1:2379", Namespace: "app"}},
		{name: "namespace slash", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: "bad/ns"}},
		{name: "namespace dotdot", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: ".."}},
		{name: "namespace leading space", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: " app"}},
		{name: "namespace trailing control", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: "app\n"}},
		{name: "rule namespace slash", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: "app", RuleNamespace: "bad/ns"}},
		{name: "rule namespace dotdot", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: "app", RuleNamespace: ".."}},
		{name: "prefix dotdot", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: "app", KeyPrefix: "cfg/../prod"}},
		{name: "partial mtls", opts: Options{Endpoints: "127.0.0.1:2379", Namespace: "app", ClientCert: "client.crt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.opts.client = &fakeClient{}
			if _, err := New(tt.opts); err == nil {
				t.Fatal("New() error = nil, want fail-closed error")
			}
		})
	}
}

func TestNormalizeEndpointsAcceptsBareHostPort(t *testing.T) {
	t.Parallel()
	endpoints, err := normalizeEndpoints("127.0.0.1:2379,https://etcd.example:2379")
	if err != nil {
		t.Fatalf("normalizeEndpoints() error = %v", err)
	}
	want := []string{"http://127.0.0.1:2379", "https://etcd.example:2379"}
	for i := range want {
		if endpoints[i] != want[i] {
			t.Fatalf("endpoint[%d] = %q, want %q", i, endpoints[i], want[i])
		}
	}
}

func TestInvalidCoordinatePartsAreRejectedBeforeRPC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		coord cfgov.Coordinate
		call  func(context.Context, *Backend, cfgov.Coordinate) error
	}{
		{name: "get namespace slash", coord: cfgov.Coordinate{Namespace: "prod/other", Key: "app"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Get(ctx, c)
			return err
		}},
		{name: "put namespace dotdot", coord: cfgov.Coordinate{Namespace: "..", Key: "app"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Put(ctx, cfgov.PutRequest{Coordinate: c, Content: []byte("x")})
			return err
		}},
		{name: "delete key backslash", coord: cfgov.Coordinate{Namespace: "prod", Key: `bad\key`}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			return b.Delete(ctx, cfgov.DeleteRequest{Coordinate: c})
		}},
		{name: "watch key control", coord: cfgov.Coordinate{Namespace: "prod", Key: "bad\nkey"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Watch(ctx, c, "", cfgov.WatchOptions{LongPoll: time.Millisecond})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeClient{}
			backend := newTestBackend(fake)
			err := tt.call(context.Background(), backend, tt.coord)
			if err == nil {
				t.Fatal("operation error = nil, want validation error")
			}
			if fake.calls != 0 {
				t.Fatalf("RPC calls = %d, want 0 before validation succeeds", fake.calls)
			}
		})
	}
}

func TestListUsesNamespacePrefixAndDoesNotLeakAcrossNamespaces(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{
		getResp: &clientv3.GetResponse{Kvs: []*mvccpb.KeyValue{
			{Key: []byte("cfg/prod/app"), Value: []byte("ok"), ModRevision: 11},
			{Key: []byte("cfg/prod/db"), Value: []byte("ok"), ModRevision: 12},
			{Key: []byte("cfg/prod/nested/key"), Value: []byte("bad"), ModRevision: 13},
			{Key: []byte("cfg/prod/.."), Value: []byte("bad"), ModRevision: 14},
			{Key: []byte("cfg/prod2/leak"), Value: []byte("bad"), ModRevision: 15},
		}},
	}
	backend := newTestBackend(fake)
	items, err := backend.List(context.Background(), cfgov.ListOptions{Namespace: "prod", Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if fake.lastGetKey != "cfg/prod/" {
		t.Fatalf("Get prefix = %q, want cfg/prod/", fake.lastGetKey)
	}
	if len(items) != 2 {
		t.Fatalf("List() len = %d, want 2: %#v", len(items), items)
	}
	if items[0].Coordinate.Key != "app" || items[1].Coordinate.Key != "db" {
		t.Fatalf("List() keys = %#v, want app/db only", items)
	}
}

func TestCASConflictMapsToAppConflict(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{txn: &fakeTxn{succeeded: false}}
	backend := newTestBackend(fake)
	_, err := backend.Put(context.Background(), cfgov.PutRequest{Coordinate: cfgov.Coordinate{Namespace: "prod", Key: "app"}, Content: []byte("x"), ExpectedRevision: "7"})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("Put() code = %s, want %s", got, apperrors.CodeConflict)
	}
	_, err = backend.Put(context.Background(), cfgov.PutRequest{
		Coordinate:    cfgov.Coordinate{Namespace: "prod", Key: "new"},
		Content:       []byte("x"),
		RequireAbsent: true,
	})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("Put(require absent) code = %s, want %s", got, apperrors.CodeConflict)
	}
}

func TestWatchTimeoutReturnsUnchanged(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{watchCh: make(chan clientv3.WatchResponse)}
	backend := newTestBackend(fake)
	event, err := backend.Watch(context.Background(), cfgov.Coordinate{Namespace: "prod", Key: "app"}, "3", cfgov.WatchOptions{LongPoll: time.Millisecond})
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	if event.Changed || event.Revision != "3" {
		t.Fatalf("Watch() = %#v, want unchanged revision 3", event)
	}
}

func TestCapabilitiesAndUnsupportedHistory(t *testing.T) {
	t.Parallel()
	backend := newTestBackend(&fakeClient{})
	caps := backend.Capabilities()
	if caps.Backend != "etcd" || !caps.SupportsWatch || !caps.SupportsCAS || !caps.SupportsRevision || caps.SupportsHistory || !caps.SupportsRules || !caps.SupportsFlags {
		t.Fatalf("Capabilities() = %#v", caps)
	}
	if !hasString(caps.ResourceTypes, "flag") {
		t.Fatalf("Capabilities().ResourceTypes = %#v, want flag", caps.ResourceTypes)
	}
	if _, _, err := backend.History(context.Background(), cfgov.Coordinate{Namespace: "prod", Key: "app"}, cfgov.HistoryOptions{}); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("History() error = %v, want NOT_IMPLEMENTED", err)
	}
}

func TestRuleCoordinateDerivesSentinelRuleKeys(t *testing.T) {
	t.Parallel()
	backend := newTestBackend(&fakeClient{})
	tests := []struct {
		ruleType string
		key      string
	}{
		{ruleType: "flow", key: "demo-flow-rules"},
		{ruleType: "degrade", key: "demo-degrade-rules"},
		{ruleType: "system", key: "demo-system-rules"},
		{ruleType: "authority", key: "demo-authority-rules"},
		{ruleType: "param", key: "demo-param-rules"},
	}
	for _, tt := range tests {
		t.Run(tt.ruleType, func(t *testing.T) {
			t.Parallel()
			coord, err := backend.RuleCoordinate("demo", tt.ruleType)
			if err != nil {
				t.Fatalf("RuleCoordinate() error = %v", err)
			}
			if coord.Namespace != "SENTINEL" || coord.Key != tt.key {
				t.Fatalf("RuleCoordinate() = %#v, want SENTINEL/%s", coord, tt.key)
			}
		})
	}
}

func TestRuleCoordinateRuleNamespaceDefaultAndOverride(t *testing.T) {
	t.Parallel()
	defaultBackend, err := New(Options{Endpoints: "127.0.0.1:2379", Namespace: "prod", client: &fakeClient{}})
	if err != nil {
		t.Fatalf("New(default) error = %v", err)
	}
	defaultCoord, err := defaultBackend.RuleCoordinate("demo", "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate(default) error = %v", err)
	}
	if defaultCoord.Namespace != "SENTINEL" {
		t.Fatalf("default namespace = %q, want SENTINEL", defaultCoord.Namespace)
	}
	overrideBackend, err := New(Options{Endpoints: "127.0.0.1:2379", Namespace: "prod", RuleNamespace: "RULES", client: &fakeClient{}})
	if err != nil {
		t.Fatalf("New(override) error = %v", err)
	}
	overrideCoord, err := overrideBackend.RuleCoordinate("demo", "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate(override) error = %v", err)
	}
	if overrideCoord.Namespace != "RULES" {
		t.Fatalf("override namespace = %q, want RULES", overrideCoord.Namespace)
	}
}

func TestRuleCoordinateRejectsUnsafeParts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		app         string
		ruleNS      string
		wantErrCode apperrors.Code
	}{
		{name: "app slash", app: "bad/app", ruleNS: "SENTINEL", wantErrCode: apperrors.CodeValidationFailed},
		{name: "app dotdot", app: "..", ruleNS: "SENTINEL", wantErrCode: apperrors.CodeUsageError},
		{name: "app control", app: "bad\napp", ruleNS: "SENTINEL", wantErrCode: apperrors.CodeValidationFailed},
		{name: "app leading space", app: " demo", ruleNS: "SENTINEL", wantErrCode: apperrors.CodeValidationFailed},
		{name: "rule namespace slash", app: "demo", ruleNS: "bad/ns", wantErrCode: apperrors.CodeValidationFailed},
		{name: "rule namespace dotdot", app: "demo", ruleNS: "..", wantErrCode: apperrors.CodeValidationFailed},
		{name: "rule namespace control", app: "demo", ruleNS: "bad\nns", wantErrCode: apperrors.CodeValidationFailed},
		{name: "rule namespace leading space", app: "demo", ruleNS: " SENTINEL", wantErrCode: apperrors.CodeValidationFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			backend := newTestBackend(&fakeClient{})
			backend.ruleNamespace = tt.ruleNS
			_, err := backend.RuleCoordinate(tt.app, "flow")
			if got := apperrors.AsAppError(err).Code; got != tt.wantErrCode {
				t.Fatalf("RuleCoordinate() code = %s, want %s (err=%v)", got, tt.wantErrCode, err)
			}
		})
	}
}

func TestFlagCoordinateUsesConfigNamespace(t *testing.T) {
	t.Parallel()
	backend := newTestBackend(&fakeClient{})
	tests := map[string]string{
		"demo":          "demo-flags",
		"order-service": "order-service-flags",
		"app1":          "app1-flags",
		"a.b":           "a.b-flags",
		"blue-green-1":  "blue-green-1-flags",
	}
	for app, wantKey := range tests {
		t.Run(app, func(t *testing.T) {
			t.Parallel()
			coord, err := backend.FlagCoordinate(app)
			if err != nil {
				t.Fatalf("FlagCoordinate() error = %v", err)
			}
			if coord.Namespace != "prod" || coord.Key != wantKey {
				t.Fatalf("coord = %#v, want prod/%s", coord, wantKey)
			}
			_, _, fullKey, err := backend.resolve(coord)
			if err != nil {
				t.Fatalf("resolve(flag coord) error = %v", err)
			}
			if fullKey != "cfg/prod/"+wantKey {
				t.Fatalf("full key = %q, want cfg/prod/%s", fullKey, wantKey)
			}
		})
	}
}

func TestFlagCoordinateRejectsUnsafeAppBeforeRPC(t *testing.T) {
	t.Parallel()
	tests := []string{"../x", "a/b", "..", "", "bad\x00app", `bad\app`, " app"}
	for _, app := range tests {
		t.Run(strings.ReplaceAll(app, "\x00", "\\x00"), func(t *testing.T) {
			t.Parallel()
			fake := &fakeClient{}
			backend := newTestBackend(fake)
			if _, err := backend.FlagCoordinate(app); err == nil {
				t.Fatalf("FlagCoordinate(%q) error = nil, want fail-closed", app)
			}
			if fake.calls != 0 {
				t.Fatalf("FlagCoordinate(%q) RPC calls = %d, want 0", app, fake.calls)
			}
		})
	}
}

func hasString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func newTestBackend(client *fakeClient) *Backend {
	return &Backend{
		endpoints:     []string{"http://127.0.0.1:2379"},
		server:        "http://127.0.0.1:2379",
		keyPrefix:     "cfg/",
		namespace:     "prod",
		ruleNamespace: "SENTINEL",
		client:        client,
		traceOut:      ioDiscard{},
	}
}

type fakeClient struct {
	calls      int
	getResp    *clientv3.GetResponse
	getErr     error
	putErr     error
	deleteErr  error
	txn        clientv3.Txn
	watchCh    chan clientv3.WatchResponse
	lastGetKey string
}

func (f *fakeClient) Get(_ context.Context, key string, _ ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	f.calls++
	f.lastGetKey = key
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResp != nil {
		return f.getResp, nil
	}
	return &clientv3.GetResponse{}, nil
}

func (f *fakeClient) Put(context.Context, string, string, ...clientv3.OpOption) (*clientv3.PutResponse, error) {
	f.calls++
	return &clientv3.PutResponse{}, f.putErr
}

func (f *fakeClient) Delete(context.Context, string, ...clientv3.OpOption) (*clientv3.DeleteResponse, error) {
	f.calls++
	return &clientv3.DeleteResponse{}, f.deleteErr
}

func (f *fakeClient) Txn(context.Context) clientv3.Txn {
	f.calls++
	if f.txn != nil {
		return f.txn
	}
	return &fakeTxn{succeeded: true}
}

func (f *fakeClient) Watch(context.Context, string, ...clientv3.OpOption) clientv3.WatchChan {
	f.calls++
	if f.watchCh == nil {
		ch := make(chan clientv3.WatchResponse)
		close(ch)
		return ch
	}
	return f.watchCh
}

type fakeTxn struct {
	succeeded bool
	err       error
}

func (t *fakeTxn) If(...clientv3.Cmp) clientv3.Txn  { return t }
func (t *fakeTxn) Then(...clientv3.Op) clientv3.Txn { return t }
func (t *fakeTxn) Else(...clientv3.Op) clientv3.Txn { return t }

func (t *fakeTxn) Commit() (*clientv3.TxnResponse, error) {
	if t.err != nil {
		return nil, t.err
	}
	return &clientv3.TxnResponse{Succeeded: t.succeeded}, nil
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	if p == nil {
		return 0, errors.New("nil write")
	}
	return len(p), nil
}
