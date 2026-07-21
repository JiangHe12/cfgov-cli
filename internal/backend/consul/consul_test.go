package consul

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
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
	_, err = backend.Put(context.Background(), cfgov.PutRequest{
		Coordinate:    cfgov.Coordinate{Namespace: "prod", Key: "new"},
		Content:       []byte("x"),
		RequireAbsent: true,
	})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("Put(require absent) code = %s, want %s (err=%v)", got, apperrors.CodeConflict, err)
	}
	if fake.lastCASModifyIndex != 0 {
		t.Fatalf("Put(require absent) CAS index = %d, want 0", fake.lastCASModifyIndex)
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
	if !hasString(caps.ResourceTypes, "rule") || !hasString(caps.ResourceTypes, "flag") || !hasString(caps.ResourceTypes, "service") {
		t.Fatalf("ResourceTypes = %#v, want rule, flag, and service", caps.ResourceTypes)
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

func TestServiceRegistryListGetInstances(t *testing.T) {
	t.Parallel()
	catalog := &fakeCatalog{
		services: map[string][]string{
			"billing": {},
			"orders":  {"v1"},
			"bad/svc": {"skip"},
		},
		catalogServices: map[string][]*capi.CatalogService{
			"orders": {
				{
					ServiceTags: []string{"v1", "blue"},
				},
				{
					ServiceTags: []string{"v2"},
				},
			},
		},
	}
	health := &fakeHealth{
		entries: map[string][]*capi.ServiceEntry{
			"orders": {
				{
					Node: &capi.Node{Address: "10.0.0.10"},
					Service: &capi.AgentService{
						Address: "10.0.0.11",
						Port:    8080,
						Meta:    map[string]string{"group": "DEFAULT_GROUP", "zone": "az1"},
						Weights: capi.AgentWeights{Passing: 7, Warning: 1},
					},
					Checks: capi.HealthChecks{{CheckID: "service:orders", Status: capi.HealthPassing}},
				},
				{
					Node: &capi.Node{Address: "10.0.0.12"},
					Service: &capi.AgentService{
						Port: 9090,
						Meta: map[string]string{"group": "other"},
					},
					Checks: capi.HealthChecks{{CheckID: "service:orders", Status: capi.HealthCritical}},
				},
			},
		},
	}
	backend := newServiceTestBackend(catalog, health, &fakeAgent{})

	list, err := backend.ListServices(context.Background(), 1, 1)
	if err != nil {
		t.Fatalf("ListServices() error = %v", err)
	}
	if list.Count != 2 || len(list.Names) != 1 || list.Names[0] != "billing" {
		t.Fatalf("ListServices() = %#v, want first of two valid sorted services", list)
	}

	item, err := backend.GetService(context.Background(), "orders")
	if err != nil {
		t.Fatalf("GetService() error = %v", err)
	}
	if item["name"] != "orders" || item["instances"] != 2 {
		t.Fatalf("GetService() = %#v", item)
	}

	instances, err := backend.ListInstances(context.Background(), "orders", "DEFAULT_GROUP")
	if err != nil {
		t.Fatalf("ListInstances() error = %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("ListInstances() len = %d, want 1: %#v", len(instances), instances)
	}
	got := instances[0]
	if got.IP != "10.0.0.11" || got.Port != 8080 || !got.Healthy || !got.Enabled || got.Weight != 7 || got.Metadata["zone"] != "az1" {
		t.Fatalf("ListInstances()[0] = %#v", got)
	}
}

func TestServiceRegistryListInstancesUsesHealthChecks(t *testing.T) {
	t.Parallel()
	health := &fakeHealth{
		entries: map[string][]*capi.ServiceEntry{
			"orders": {
				{
					Node:    &capi.Node{Address: "10.0.0.10"},
					Service: &capi.AgentService{Port: 8080},
					Checks:  capi.HealthChecks{{CheckID: "service:orders", Status: capi.HealthCritical}},
				},
				{
					Node:    &capi.Node{Address: "10.0.0.11"},
					Service: &capi.AgentService{Port: 8081},
					Checks:  capi.HealthChecks{{CheckID: "service:orders", Status: capi.HealthWarning}},
				},
				{
					Node:    &capi.Node{Address: "10.0.0.12"},
					Service: &capi.AgentService{Port: 8082},
					Checks:  capi.HealthChecks{{CheckID: "service:orders", Status: capi.HealthPassing}},
				},
			},
		},
	}
	backend := newServiceTestBackend(&fakeCatalog{}, health, &fakeAgent{})
	instances, err := backend.ListInstances(context.Background(), "orders", "")
	if err != nil {
		t.Fatalf("ListInstances() error = %v", err)
	}
	if len(instances) != 3 {
		t.Fatalf("ListInstances() len = %d, want 3: %#v", len(instances), instances)
	}
	if instances[0].Healthy || instances[1].Healthy || !instances[2].Healthy {
		t.Fatalf("health flags = %v/%v/%v, want false/false/true", instances[0].Healthy, instances[1].Healthy, instances[2].Healthy)
	}
	if health.calls != 1 || health.lastService != "orders" || health.lastPassingOnly {
		t.Fatalf("health call = calls:%d service:%q passingOnly:%v", health.calls, health.lastService, health.lastPassingOnly)
	}
}

func TestServiceRegistryRegisterDeregister(t *testing.T) {
	t.Parallel()
	ephemeral := false
	agent := &fakeAgent{}
	backend := newServiceTestBackend(&fakeCatalog{}, &fakeHealth{}, agent)
	opts := cfgov.InstanceOptions{
		GroupName: "DEFAULT_GROUP",
		Cluster:   "blue",
		Weight:    3,
		Ephemeral: &ephemeral,
		Metadata:  map[string]string{"owner": "ops"},
	}

	if err := backend.RegisterInstance(context.Background(), "orders", "10.0.0.11", 8080, opts); err != nil {
		t.Fatalf("RegisterInstance() error = %v", err)
	}
	if agent.registerCalls != 1 {
		t.Fatalf("registerCalls = %d, want 1", agent.registerCalls)
	}
	reg := agent.lastRegister
	if reg.ID != "orders-10.0.0.11-8080" || reg.Name != "orders" || reg.Address != "10.0.0.11" || reg.Port != 8080 {
		t.Fatalf("registration = %#v", reg)
	}
	if reg.Meta["owner"] != "ops" || reg.Meta["group"] != "DEFAULT_GROUP" || reg.Meta["cluster"] != "blue" || reg.Meta["ephemeral"] != "false" {
		t.Fatalf("registration meta = %#v", reg.Meta)
	}
	if reg.Weights == nil || reg.Weights.Passing != 3 || reg.Weights.Warning != 3 {
		t.Fatalf("registration weights = %#v", reg.Weights)
	}

	if err := backend.DeregisterInstance(context.Background(), "orders", "10.0.0.11", 8080, opts); err != nil {
		t.Fatalf("DeregisterInstance() error = %v", err)
	}
	if agent.deregisterCalls != 1 || agent.lastDeregister != "orders-10.0.0.11-8080" {
		t.Fatalf("deregisterCalls=%d id=%q", agent.deregisterCalls, agent.lastDeregister)
	}
}

func TestServiceRegistryRejectsUnsafeInputsBeforeRPC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		call func(*Backend) error
	}{
		{name: "list instances service slash", call: func(b *Backend) error {
			_, err := b.ListInstances(context.Background(), "bad/service", "")
			return err
		}},
		{name: "get service control", call: func(b *Backend) error {
			_, err := b.GetService(context.Background(), "bad\nservice")
			return err
		}},
		{name: "register bad ip", call: func(b *Backend) error {
			return b.RegisterInstance(context.Background(), "orders", "not-an-ip", 8080, cfgov.InstanceOptions{})
		}},
		{name: "register bad port", call: func(b *Backend) error {
			return b.RegisterInstance(context.Background(), "orders", "10.0.0.11", 0, cfgov.InstanceOptions{})
		}},
		{name: "deregister service leading space", call: func(b *Backend) error {
			return b.DeregisterInstance(context.Background(), " orders", "10.0.0.11", 8080, cfgov.InstanceOptions{})
		}},
		{name: "register metadata control", call: func(b *Backend) error {
			return b.RegisterInstance(context.Background(), "orders", "10.0.0.11", 8080, cfgov.InstanceOptions{Metadata: map[string]string{"k": "bad\nvalue"}})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			catalog := &fakeCatalog{}
			health := &fakeHealth{}
			agent := &fakeAgent{}
			backend := newServiceTestBackend(catalog, health, agent)
			if err := tt.call(backend); err == nil {
				t.Fatal("operation error = nil, want validation error")
			}
			if catalog.calls != 0 || health.calls != 0 || agent.calls != 0 {
				t.Fatalf("RPC calls catalog=%d health=%d agent=%d, want 0", catalog.calls, health.calls, agent.calls)
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

func newTestBackend(kv *fakeKV) *Backend {
	backend, err := New(Options{Server: "127.0.0.1:8500", KeyPrefix: "cfg", Namespace: "prod", kv: kv, TraceOut: ioDiscard{}})
	if err != nil {
		panic(err)
	}
	return backend
}

func newServiceTestBackend(catalog *fakeCatalog, health *fakeHealth, agent *fakeAgent) *Backend {
	backend := newTestBackend(&fakeKV{})
	backend.catalog = catalog
	backend.health = health
	backend.agent = agent
	return backend
}

type fakeKV struct {
	calls              int
	keysCalls          int
	pair               *capi.KVPair
	pairs              capi.KVPairs
	getErr             error
	listErr            error
	putErr             error
	casErr             error
	deleteErr          error
	deleteCASErr       error
	casOK              bool
	deleteCASOK        bool
	lastGetKey         string
	lastListPrefix     string
	lastKeysPrefix     string
	lastKeysSeparator  string
	lastQuery          *capi.QueryOptions
	lastCASModifyIndex uint64
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

func (f *fakeKV) CAS(pair *capi.KVPair, _ *capi.WriteOptions) (bool, *capi.WriteMeta, error) {
	f.calls++
	f.lastCASModifyIndex = pair.ModifyIndex
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

type fakeCatalog struct {
	calls           int
	services        map[string][]string
	catalogServices map[string][]*capi.CatalogService
	err             error
	lastService     string
}

func (f *fakeCatalog) Services(*capi.QueryOptions) (map[string][]string, *capi.QueryMeta, error) {
	f.calls++
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.services, &capi.QueryMeta{}, nil
}

func (f *fakeCatalog) Service(service, tag string, _ *capi.QueryOptions) ([]*capi.CatalogService, *capi.QueryMeta, error) {
	f.calls++
	f.lastService = service
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.catalogServices[service], &capi.QueryMeta{}, nil
}

type fakeHealth struct {
	calls           int
	entries         map[string][]*capi.ServiceEntry
	err             error
	lastService     string
	lastPassingOnly bool
}

func (f *fakeHealth) Service(service, tag string, passingOnly bool, _ *capi.QueryOptions) ([]*capi.ServiceEntry, *capi.QueryMeta, error) {
	f.calls++
	f.lastService = service
	f.lastPassingOnly = passingOnly
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.entries[service], &capi.QueryMeta{}, nil
}

type fakeAgent struct {
	calls           int
	registerCalls   int
	deregisterCalls int
	err             error
	lastRegister    *capi.AgentServiceRegistration
	lastDeregister  string
}

func (f *fakeAgent) ServiceRegisterOpts(service *capi.AgentServiceRegistration, _ capi.ServiceRegisterOpts) error {
	f.calls++
	f.registerCalls++
	f.lastRegister = service
	return f.err
}

func (f *fakeAgent) ServiceDeregisterOpts(serviceID string, _ *capi.QueryOptions) error {
	f.calls++
	f.deregisterCalls++
	f.lastDeregister = serviceID
	return f.err
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	if p == nil {
		return 0, errors.New("nil write")
	}
	return len(p), nil
}
