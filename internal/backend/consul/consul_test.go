package consul

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	capi "github.com/hashicorp/consul/api"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestNewValidatesConsulOptionsFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts Options
	}{
		{name: "missing server", opts: Options{Namespace: "app"}},
		{name: "bad scheme", opts: Options{Server: "ftp://127.0.0.1:8500", Namespace: "app"}},
		{name: "server credentials", opts: Options{Server: "http://user:pass@127.0.0.1:8500", Namespace: "app"}},
		{name: "server path", opts: Options{Server: "http://127.0.0.1:8500/v1", Namespace: "app"}},
		{name: "namespace slash", opts: Options{Server: "127.0.0.1:8500", Namespace: "bad/ns"}},
		{name: "namespace dotdot", opts: Options{Server: "127.0.0.1:8500", Namespace: ".."}},
		{name: "namespace leading space", opts: Options{Server: "127.0.0.1:8500", Namespace: " app"}},
		{name: "namespace trailing control", opts: Options{Server: "127.0.0.1:8500", Namespace: "app\n"}},
		{name: "rule namespace slash", opts: Options{Server: "127.0.0.1:8500", Namespace: "app", RuleNamespace: "bad/ns"}},
		{name: "rule namespace dotdot", opts: Options{Server: "127.0.0.1:8500", Namespace: "app", RuleNamespace: ".."}},
		{name: "prefix dotdot", opts: Options{Server: "127.0.0.1:8500", Namespace: "app", KeyPrefix: "cfg/../prod"}},
		{name: "partial mtls", opts: Options{Server: "127.0.0.1:8500", Namespace: "app", ClientCert: "client.crt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.opts.kv = &fakeKV{}
			if _, err := New(tt.opts); err == nil {
				t.Fatal("New() error = nil, want fail-closed error")
			}
		})
	}
}

func TestNormalizeServerAcceptsBareHostPort(t *testing.T) {
	t.Parallel()
	server, parsed, err := normalizeServer("127.0.0.1:8500")
	if err != nil {
		t.Fatalf("normalizeServer() error = %v", err)
	}
	if server != "http://127.0.0.1:8500" || parsed.Scheme != "http" || parsed.Host != "127.0.0.1:8500" {
		t.Fatalf("server = %q parsed=%#v", server, parsed)
	}
}

func TestResolveDerivesFullKey(t *testing.T) {
	t.Parallel()
	backend := newTestBackend(&fakeKV{})
	tests := []struct {
		name      string
		namespace string
		key       string
		fullKey   string
	}{
		{name: "plain", namespace: "prod", key: "app", fullKey: "cfg/prod/app"},
		{name: "dash", namespace: "prod", key: "order-service", fullKey: "cfg/prod/order-service"},
		{name: "digit", namespace: "prod1", key: "app1", fullKey: "cfg/prod1/app1"},
		{name: "dot", namespace: "prod", key: "a.b", fullKey: "cfg/prod/a.b"},
		{name: "blue green", namespace: "blue-green-1", key: "feature-1", fullKey: "cfg/blue-green-1/feature-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, fullKey, err := backend.resolve(cfgov.Coordinate{Namespace: tt.namespace, Key: tt.key})
			if err != nil {
				t.Fatalf("resolve() error = %v", err)
			}
			if fullKey != tt.fullKey {
				t.Fatalf("fullKey = %q, want %q", fullKey, tt.fullKey)
			}
		})
	}
}

func TestInvalidCoordinatePartsAreRejectedBeforeRPC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		coord cfgov.Coordinate
		call  func(context.Context, *Backend, cfgov.Coordinate) error
	}{
		{name: "get namespace dotdot path", coord: cfgov.Coordinate{Namespace: "../other", Key: "app"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Get(ctx, c)
			return err
		}},
		{name: "put namespace slash", coord: cfgov.Coordinate{Namespace: "a/b", Key: "app"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Put(ctx, cfgov.PutRequest{Coordinate: c, Content: []byte("x")})
			return err
		}},
		{name: "delete namespace dotdot", coord: cfgov.Coordinate{Namespace: "..", Key: "app"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			return b.Delete(ctx, cfgov.DeleteRequest{Coordinate: c})
		}},
		{name: "watch namespace empty", coord: cfgov.Coordinate{Namespace: "", Key: ""}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Watch(ctx, c, "", cfgov.WatchOptions{})
			return err
		}},
		{name: "get namespace nul", coord: cfgov.Coordinate{Namespace: "bad\x00ns", Key: "app"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Get(ctx, c)
			return err
		}},
		{name: "get namespace backslash", coord: cfgov.Coordinate{Namespace: `bad\ns`, Key: "app"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Get(ctx, c)
			return err
		}},
		{name: "get key dotdot path", coord: cfgov.Coordinate{Namespace: "prod", Key: "../other"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Get(ctx, c)
			return err
		}},
		{name: "put key slash", coord: cfgov.Coordinate{Namespace: "prod", Key: "a/b"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Put(ctx, cfgov.PutRequest{Coordinate: c, Content: []byte("x")})
			return err
		}},
		{name: "delete key dotdot", coord: cfgov.Coordinate{Namespace: "prod", Key: ".."}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			return b.Delete(ctx, cfgov.DeleteRequest{Coordinate: c})
		}},
		{name: "watch key empty", coord: cfgov.Coordinate{Namespace: "prod", Key: ""}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Watch(ctx, c, "", cfgov.WatchOptions{})
			return err
		}},
		{name: "get key nul", coord: cfgov.Coordinate{Namespace: "prod", Key: "bad\x00key"}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Get(ctx, c)
			return err
		}},
		{name: "get key backslash", coord: cfgov.Coordinate{Namespace: "prod", Key: `bad\key`}, call: func(ctx context.Context, b *Backend, c cfgov.Coordinate) error {
			_, err := b.Get(ctx, c)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.name, "\x00", "\\x00"), func(t *testing.T) {
			t.Parallel()
			fake := &fakeKV{}
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
	fake := &fakeKV{pairs: capi.KVPairs{
		{Key: "cfg/prod/app", Value: []byte("ok"), ModifyIndex: 11},
		{Key: "cfg/prod/db", Value: []byte("ok"), ModifyIndex: 12},
		{Key: "cfg/prod/nested/key", Value: []byte("bad"), ModifyIndex: 13},
		{Key: "cfg/prod/..", Value: []byte("bad"), ModifyIndex: 14},
		{Key: "cfg/prod2/leak", Value: []byte("bad"), ModifyIndex: 15},
	}}
	backend := newTestBackend(fake)
	items, err := backend.List(context.Background(), cfgov.ListOptions{Namespace: "prod", Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if fake.lastListPrefix != "cfg/prod/" {
		t.Fatalf("List prefix = %q, want cfg/prod/", fake.lastListPrefix)
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
	fake := &fakeKV{casOK: false, deleteCASOK: false}
	backend := newTestBackend(fake)
	_, err := backend.Put(context.Background(), cfgov.PutRequest{Coordinate: cfgov.Coordinate{Namespace: "prod", Key: "app"}, Content: []byte("x"), ExpectedRevision: "7"})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("Put() code = %s, want %s (err=%v)", got, apperrors.CodeConflict, err)
	}
	err = backend.Delete(context.Background(), cfgov.DeleteRequest{Coordinate: cfgov.Coordinate{Namespace: "prod", Key: "app"}, ExpectedRevision: "7"})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("Delete() code = %s, want %s (err=%v)", got, apperrors.CodeConflict, err)
	}
}

func TestWatchUsesBlockingQuery(t *testing.T) {
	t.Parallel()
	fake := &fakeKV{pair: &capi.KVPair{Key: "cfg/prod/app", Value: []byte("v"), ModifyIndex: 8}}
	backend := newTestBackend(fake)
	event, err := backend.Watch(context.Background(), cfgov.Coordinate{Namespace: "prod", Key: "app"}, "7", cfgov.WatchOptions{})
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}
	if !event.Changed || event.Revision != "8" {
		t.Fatalf("Watch() = %#v, want changed revision 8", event)
	}
	if fake.lastQuery == nil || fake.lastQuery.WaitIndex != 7 {
		t.Fatalf("WaitIndex = %#v, want 7", fake.lastQuery)
	}
}

func TestCapabilities(t *testing.T) {
	t.Parallel()
	caps := newTestBackend(&fakeKV{}).Capabilities()
	if caps.Backend != "consul" || !caps.SupportsWatch || !caps.SupportsCAS || !caps.SupportsRevision || caps.SupportsHistory || !caps.SupportsRules || !caps.SupportsFlags {
		t.Fatalf("Capabilities() = %#v", caps)
	}
	if !hasString(caps.ResourceTypes, "rule") || !hasString(caps.ResourceTypes, "flag") {
		t.Fatalf("ResourceTypes = %#v, want rule and flag", caps.ResourceTypes)
	}
}

func TestRuleCoordinateDerivesSentinelRuleKeys(t *testing.T) {
	t.Parallel()
	backend := newTestBackend(&fakeKV{})
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
			_, _, fullKey, err := backend.resolve(coord)
			if err != nil {
				t.Fatalf("resolve(rule coord) error = %v", err)
			}
			if fullKey != "cfg/SENTINEL/"+tt.key {
				t.Fatalf("full key = %q, want cfg/SENTINEL/%s", fullKey, tt.key)
			}
		})
	}
}

func TestRuleCoordinateRuleNamespaceDefaultAndOverride(t *testing.T) {
	t.Parallel()
	defaultBackend, err := New(Options{Server: "127.0.0.1:8500", Namespace: "prod", kv: &fakeKV{}})
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
	overrideBackend, err := New(Options{Server: "127.0.0.1:8500", Namespace: "prod", RuleNamespace: "RULES", kv: &fakeKV{}})
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
			backend := newTestBackend(&fakeKV{})
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
	backend := newTestBackend(&fakeKV{})
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
			fake := &fakeKV{}
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

func TestPingUsesKeysWithoutFetchingValues(t *testing.T) {
	t.Parallel()
	fake := &fakeKV{}
	backend := newTestBackend(fake)
	if err := backend.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if fake.keysCalls != 1 || fake.calls != 1 {
		t.Fatalf("calls = %d keysCalls = %d, want only one Keys call", fake.calls, fake.keysCalls)
	}
	if fake.lastKeysPrefix != "cfg/" || fake.lastKeysSeparator != "/" {
		t.Fatalf("Keys(%q, %q), want cfg/, /", fake.lastKeysPrefix, fake.lastKeysSeparator)
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

func newTestBackend(kv *fakeKV) *Backend {
	backend, err := New(Options{Server: "127.0.0.1:8500", KeyPrefix: "cfg", Namespace: "prod", kv: kv, TraceOut: ioDiscard{}})
	if err != nil {
		panic(err)
	}
	return backend
}

type fakeKV struct {
	calls             int
	keysCalls         int
	pair              *capi.KVPair
	pairs             capi.KVPairs
	getErr            error
	listErr           error
	putErr            error
	casErr            error
	deleteErr         error
	deleteCASErr      error
	casOK             bool
	deleteCASOK       bool
	lastGetKey        string
	lastListPrefix    string
	lastKeysPrefix    string
	lastKeysSeparator string
	lastQuery         *capi.QueryOptions
}

func (f *fakeKV) Get(key string, q *capi.QueryOptions) (*capi.KVPair, *capi.QueryMeta, error) {
	f.calls++
	f.lastGetKey = key
	f.lastQuery = q
	if f.getErr != nil {
		return nil, nil, f.getErr
	}
	return f.pair, &capi.QueryMeta{LastIndex: 1}, nil
}

func (f *fakeKV) List(prefix string, q *capi.QueryOptions) (capi.KVPairs, *capi.QueryMeta, error) {
	f.calls++
	f.lastListPrefix = prefix
	f.lastQuery = q
	return f.pairs, &capi.QueryMeta{LastIndex: 1}, f.listErr
}

func (f *fakeKV) Keys(prefix, separator string, q *capi.QueryOptions) ([]string, *capi.QueryMeta, error) {
	f.calls++
	f.keysCalls++
	f.lastKeysPrefix = prefix
	f.lastKeysSeparator = separator
	f.lastQuery = q
	return []string{"cfg/prod/"}, &capi.QueryMeta{LastIndex: 1}, f.listErr
}

func (f *fakeKV) Put(*capi.KVPair, *capi.WriteOptions) (*capi.WriteMeta, error) {
	f.calls++
	return &capi.WriteMeta{}, f.putErr
}

func (f *fakeKV) CAS(*capi.KVPair, *capi.WriteOptions) (bool, *capi.WriteMeta, error) {
	f.calls++
	return f.casOK, &capi.WriteMeta{}, f.casErr
}

func (f *fakeKV) Delete(string, *capi.WriteOptions) (*capi.WriteMeta, error) {
	f.calls++
	return &capi.WriteMeta{}, f.deleteErr
}

func (f *fakeKV) DeleteCAS(*capi.KVPair, *capi.WriteOptions) (bool, *capi.WriteMeta, error) {
	f.calls++
	return f.deleteCASOK, &capi.WriteMeta{}, f.deleteCASErr
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	if p == nil {
		return 0, errors.New("nil write")
	}
	return len(p), nil
}
