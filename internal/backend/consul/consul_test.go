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
	if caps.Backend != "consul" || !caps.SupportsWatch || !caps.SupportsCAS || !caps.SupportsRevision || caps.SupportsHistory || caps.SupportsRules || caps.SupportsFlags {
		t.Fatalf("Capabilities() = %#v", caps)
	}
	if len(caps.ResourceTypes) != 1 || caps.ResourceTypes[0] != "config" {
		t.Fatalf("ResourceTypes = %#v, want config only", caps.ResourceTypes)
	}
}

func newTestBackend(kv *fakeKV) *Backend {
	backend, err := New(Options{Server: "127.0.0.1:8500", KeyPrefix: "cfg", Namespace: "prod", kv: kv, TraceOut: ioDiscard{}})
	if err != nil {
		panic(err)
	}
	return backend
}

type fakeKV struct {
	calls          int
	pair           *capi.KVPair
	pairs          capi.KVPairs
	getErr         error
	listErr        error
	putErr         error
	casErr         error
	deleteErr      error
	deleteCASErr   error
	casOK          bool
	deleteCASOK    bool
	lastGetKey     string
	lastListPrefix string
	lastQuery      *capi.QueryOptions
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
