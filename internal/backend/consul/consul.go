// Package consul adapts Consul KV to cfgov.Backend.
//
// Coordinate mapping:
//   - Backend options carry a Consul HTTP endpoint, a key prefix, and a default
//     namespace.
//   - cfgov.Coordinate.Namespace maps to one opaque path segment under keyPrefix.
//   - cfgov.Coordinate.Key maps to one opaque path segment under that namespace.
//   - The full Consul KV key is "<keyPrefix><namespace>/<key>".
//
// Rule coordinate mapping:
//   - RuleCoordinate(app, type) maps to Coordinate{Namespace: ruleNamespace,
//     Key: "{app}-{type}-rules"}.
//   - ruleNamespace defaults to "SENTINEL" and is intentionally separate from
//     the config namespace default "application".
package consul

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	capi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

const (
	defaultNamespace     = "application"
	defaultRuleNamespace = "SENTINEL"
)

type Options struct {
	Server        string
	KeyPrefix     string
	Namespace     string
	RuleNamespace string
	Token         string
	CACert        string
	ClientCert    string
	ClientKey     string
	Timeout       time.Duration
	Trace         bool
	TraceOut      io.Writer

	kv      kvClient
	catalog catalogClient
	health  healthClient
	agent   agentClient
}

type Backend struct {
	server        string
	keyPrefix     string
	namespace     string
	ruleNamespace string
	token         string
	kv            kvClient
	catalog       catalogClient
	health        healthClient
	agent         agentClient
	trace         bool
	traceOut      io.Writer
}

type kvClient interface {
	Get(key string, q *capi.QueryOptions) (*capi.KVPair, *capi.QueryMeta, error)
	List(prefix string, q *capi.QueryOptions) (capi.KVPairs, *capi.QueryMeta, error)
	Keys(prefix, separator string, q *capi.QueryOptions) ([]string, *capi.QueryMeta, error)
	Put(p *capi.KVPair, q *capi.WriteOptions) (*capi.WriteMeta, error)
	CAS(p *capi.KVPair, q *capi.WriteOptions) (bool, *capi.WriteMeta, error)
	Delete(key string, w *capi.WriteOptions) (*capi.WriteMeta, error)
	DeleteCAS(p *capi.KVPair, q *capi.WriteOptions) (bool, *capi.WriteMeta, error)
}

type catalogClient interface {
	Services(q *capi.QueryOptions) (map[string][]string, *capi.QueryMeta, error)
	Service(service, tag string, q *capi.QueryOptions) ([]*capi.CatalogService, *capi.QueryMeta, error)
}

type healthClient interface {
	Service(service, tag string, passingOnly bool, q *capi.QueryOptions) ([]*capi.ServiceEntry, *capi.QueryMeta, error)
}

type agentClient interface {
	ServiceRegisterOpts(service *capi.AgentServiceRegistration, opts capi.ServiceRegisterOpts) error
	ServiceDeregisterOpts(serviceID string, q *capi.QueryOptions) error
}

var (
	_ cfgov.Backend         = (*Backend)(nil)
	_ cfgov.RuleStore       = (*Backend)(nil)
	_ cfgov.FlagStore       = (*Backend)(nil)
	_ cfgov.ServiceRegistry = (*Backend)(nil)
)

func ValidateServer(raw string) error {
	_, _, err := normalizeServer(raw)
	return err
}

func ValidateKeyPrefix(raw string) error {
	_, err := normalizeKeyPrefix(raw)
	return err
}

func New(opts Options) (*Backend, error) {
	server, apiConfig, err := consulConfig(opts)
	if err != nil {
		return nil, err
	}
	keyPrefix, err := normalizeKeyPrefix(opts.KeyPrefix)
	if err != nil {
		return nil, err
	}
	namespace := firstNonEmpty(opts.Namespace, defaultNamespace)
	if err := validatePart("namespace", namespace); err != nil {
		return nil, err
	}
	ruleNamespace := firstNonEmpty(opts.RuleNamespace, defaultRuleNamespace)
	if err := validatePart("rule namespace", ruleNamespace); err != nil {
		return nil, err
	}
	out := opts.TraceOut
	if out == nil {
		out = os.Stderr
	}
	kv := opts.kv
	catalog := opts.catalog
	health := opts.health
	agent := opts.agent
	if kv == nil {
		client, err := capi.NewClient(apiConfig)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeBackendUnreachable, "failed to create Consul client", err)
		}
		kv = client.KV()
		catalog = client.Catalog()
		health = client.Health()
		agent = client.Agent()
	}
	return &Backend{
		server:        server,
		keyPrefix:     keyPrefix,
		namespace:     namespace,
		ruleNamespace: ruleNamespace,
		token:         opts.Token,
		kv:            kv,
		catalog:       catalog,
		health:        health,
		agent:         agent,
		trace:         opts.Trace,
		traceOut:      out,
	}, nil
}

func consulConfig(opts Options) (string, *capi.Config, error) {
	server, parsed, err := normalizeServer(opts.Server)
	if err != nil {
		return "", nil, err
	}
	cfg := capi.DefaultConfigWithLogger(hclog.NewNullLogger())
	cfg.Address = parsed.Host
	cfg.Scheme = parsed.Scheme
	cfg.Token = opts.Token
	cfg.TLSConfig = capi.TLSConfig{
		Address:  parsed.Host,
		CAFile:   opts.CACert,
		CertFile: opts.ClientCert,
		KeyFile:  opts.ClientKey,
	}
	if opts.Timeout > 0 {
		cfg.WaitTime = opts.Timeout
	}
	if (opts.ClientCert == "") != (opts.ClientKey == "") {
		return "", nil, apperrors.New(apperrors.CodeUsageError, "Consul client certificate and key must be provided together", nil)
	}
	return server, cfg, nil
}

func (b *Backend) ValidateKey(key string) error {
	return validatePart("key", key)
}

func (b *Backend) Get(ctx context.Context, coord cfgov.Coordinate) (cfgov.Blob, error) {
	ns, key, fullKey, err := b.resolve(coord)
	if err != nil {
		return cfgov.Blob{}, err
	}
	b.tracef("[trace] >>> consul get %s\n", redactKey(fullKey))
	pair, _, err := b.kv.Get(fullKey, b.queryOptions(ctx))
	if err != nil {
		return cfgov.Blob{}, backendErr("consul get failed", err)
	}
	if pair == nil {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeResourceNotFound, "consul key not found", nil)
	}
	return blobFromPair(ns, key, pair), nil
}

func (b *Backend) Put(ctx context.Context, req cfgov.PutRequest) (cfgov.Blob, error) {
	if err := req.ValidatePreconditions(); err != nil {
		return cfgov.Blob{}, err
	}
	ns, key, fullKey, err := b.resolve(req.Coordinate)
	if err != nil {
		return cfgov.Blob{}, err
	}
	writeOpts := b.writeOptions(ctx)
	if req.RequireAbsent || req.ExpectedRevision != "" {
		pair, err := consulConditionalPutPair(fullKey, req)
		if err != nil {
			return cfgov.Blob{}, err
		}
		b.tracef("[trace] >>> consul cas %s value=<redacted:%d>\n", redactKey(fullKey), len(req.Content))
		ok, _, err := b.kv.CAS(pair, writeOpts)
		if err != nil {
			return cfgov.Blob{}, backendErr("consul cas failed", err)
		}
		if !ok {
			return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config precondition failed", nil)
		}
		return b.Get(ctx, cfgov.Coordinate{Namespace: ns, Key: key})
	}
	pair := &capi.KVPair{Key: fullKey, Value: req.Content}
	b.tracef("[trace] >>> consul put %s value=<redacted:%d>\n", redactKey(fullKey), len(req.Content))
	if _, err := b.kv.Put(pair, writeOpts); err != nil {
		return cfgov.Blob{}, backendErr("consul put failed", err)
	}
	return b.Get(ctx, cfgov.Coordinate{Namespace: ns, Key: key})
}

func consulConditionalPutPair(fullKey string, req cfgov.PutRequest) (*capi.KVPair, error) {
	pair := &capi.KVPair{Key: fullKey, Value: req.Content}
	if req.ExpectedRevision == "" {
		return pair, nil
	}
	revision, err := parseRevision(req.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	pair.ModifyIndex = revision
	return pair, nil
}

func (b *Backend) Delete(ctx context.Context, req cfgov.DeleteRequest) error {
	_, _, fullKey, err := b.resolve(req.Coordinate)
	if err != nil {
		return err
	}
	writeOpts := b.writeOptions(ctx)
	if req.ExpectedRevision != "" {
		rev, err := parseRevision(req.ExpectedRevision)
		if err != nil {
			return err
		}
		b.tracef("[trace] >>> consul delete-cas %s\n", redactKey(fullKey))
		ok, _, err := b.kv.DeleteCAS(&capi.KVPair{Key: fullKey, ModifyIndex: rev}, writeOpts)
		if err != nil {
			return backendErr("consul delete cas failed", err)
		}
		if !ok {
			return apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
		}
		return nil
	}
	b.tracef("[trace] >>> consul delete %s\n", redactKey(fullKey))
	if _, err := b.kv.Delete(fullKey, writeOpts); err != nil {
		return backendErr("consul delete failed", err)
	}
	return nil
}

func (b *Backend) List(ctx context.Context, opts cfgov.ListOptions) ([]cfgov.ListItem, error) {
	ns := opts.Namespace
	if ns == "" {
		ns = b.namespace
	}
	if err := validatePart("namespace", ns); err != nil {
		return nil, err
	}
	if opts.Query != "" {
		if err := b.ValidateKey(opts.Query); err != nil {
			return nil, err
		}
	}
	if opts.Prefix != "" {
		if err := validatePart("prefix", opts.Prefix); err != nil {
			return nil, err
		}
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	prefix := b.namespacePrefix(ns)
	b.tracef("[trace] >>> consul list %s\n", redactKey(prefix))
	pairs, _, err := b.kv.List(prefix, b.queryOptions(ctx))
	if err != nil {
		return nil, backendErr("consul list failed", err)
	}
	out := make([]cfgov.ListItem, 0, len(pairs))
	for _, pair := range pairs {
		item, ok := b.listItemFromPair(ns, prefix, pair, opts)
		if !ok {
			continue
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Coordinate.Key < out[j].Coordinate.Key })
	return out, nil
}

func (b *Backend) History(context.Context, cfgov.Coordinate, cfgov.HistoryOptions) ([]cfgov.HistoryItem, int, error) {
	return nil, 0, apperrors.New(apperrors.CodeNotImplemented, "consul backend does not support config history", nil)
}

func (b *Backend) Watch(ctx context.Context, coord cfgov.Coordinate, revision string, opts cfgov.WatchOptions) (cfgov.WatchEvent, error) {
	ns, key, fullKey, err := b.resolve(coord)
	if err != nil {
		return cfgov.WatchEvent{}, err
	}
	waitIndex := uint64(0)
	if revision != "" {
		waitIndex, err = parseRevision(revision)
		if err != nil {
			return cfgov.WatchEvent{}, err
		}
	}
	waitTime := opts.LongPoll
	if waitTime <= 0 {
		waitTime = 30 * time.Second
	}
	q := b.queryOptions(ctx)
	q.WaitIndex = waitIndex
	q.WaitTime = waitTime
	b.tracef("[trace] >>> consul watch %s\n", redactKey(fullKey))
	pair, meta, err := b.kv.Get(fullKey, q)
	if err != nil {
		return cfgov.WatchEvent{}, backendErr("consul watch failed", err)
	}
	nextRevision := revision
	if pair != nil {
		nextRevision = revisionString(pair.ModifyIndex)
	} else if meta != nil && meta.LastIndex > 0 {
		nextRevision = revisionString(meta.LastIndex)
	}
	return cfgov.WatchEvent{Coordinate: cfgov.Coordinate{Namespace: ns, Key: key}, Revision: nextRevision, Changed: nextRevision != revision}, nil
}

func (b *Backend) CurrentRevision(ctx context.Context, coord cfgov.Coordinate) (string, error) {
	blob, err := b.Get(ctx, coord)
	if err != nil {
		return "", err
	}
	return blob.Revision, nil
}

func (b *Backend) Ping(ctx context.Context) error {
	_, _, err := b.kv.Keys(b.keyPrefix, "/", b.queryOptions(ctx))
	if err != nil {
		return backendErr("consul ping failed", err)
	}
	return nil
}

func (b *Backend) Describe() cfgov.Description {
	return cfgov.Description{Backend: "consul", Server: b.server, Namespace: b.namespace}
}

func (b *Backend) Capabilities() cfgov.Capabilities {
	return cfgov.Capabilities{
		Backend:          "consul",
		ResourceTypes:    []string{"config", "rule", "flag", "service"},
		Verbs:            []string{"get", "list", "diff", "validate", "pull", "listen", "push", "delete"},
		SupportsCAS:      true,
		SupportsRevision: true,
		SupportsHistory:  false,
		SupportsWatch:    true,
		SupportsRules:    true,
		SupportsFlags:    true,
	}
}

func (b *Backend) RuleCoordinate(app, ruleType string) (cfgov.Coordinate, error) {
	if app != strings.TrimSpace(app) {
		return cfgov.Coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "app contains leading or trailing whitespace", nil)
	}
	parsed, err := rule.ParseType(ruleType)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	dataID, err := rule.DataID(app, parsed)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	coord := cfgov.Coordinate{Namespace: b.ruleNamespace, Key: dataID}
	if _, _, _, err := b.resolve(coord); err != nil {
		return cfgov.Coordinate{}, err
	}
	return coord, nil
}

func (b *Backend) FlagCoordinate(app string) (cfgov.Coordinate, error) {
	if app != strings.TrimSpace(app) {
		return cfgov.Coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "app contains leading or trailing whitespace", nil)
	}
	dataID, err := flag.DataID(app)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	coord := cfgov.Coordinate{Namespace: b.namespace, Key: dataID}
	if _, _, _, err := b.resolve(coord); err != nil {
		return cfgov.Coordinate{}, err
	}
	return coord, nil
}

func (b *Backend) ListServices(ctx context.Context, page, pageSize int) (cfgov.ServiceList, error) {
	if b.catalog == nil {
		return cfgov.ServiceList{}, apperrors.New(apperrors.CodeBackendUnreachable, "consul catalog client not configured", nil)
	}
	services, _, err := b.catalog.Services(b.queryOptions(ctx))
	if err != nil {
		return cfgov.ServiceList{}, backendErr("consul list services failed", err)
	}
	names := make([]string, 0, len(services))
	for name := range services {
		if err := validateServiceName(name); err != nil {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return cfgov.ServiceList{Count: len(names), Names: paginateNames(names, page, pageSize)}, nil
}

func (b *Backend) GetService(ctx context.Context, name string) (map[string]any, error) {
	if err := validateServiceName(name); err != nil {
		return nil, err
	}
	instances, err := b.catalogService(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(instances) == 0 {
		return nil, apperrors.New(apperrors.CodeResourceNotFound, "consul service not found", nil)
	}
	tags := map[string]struct{}{}
	for _, item := range instances {
		for _, tag := range item.ServiceTags {
			tags[tag] = struct{}{}
		}
	}
	outTags := make([]string, 0, len(tags))
	for tag := range tags {
		outTags = append(outTags, tag)
	}
	sort.Strings(outTags)
	return map[string]any{
		"name":      name,
		"instances": len(instances),
		"tags":      outTags,
	}, nil
}

func (b *Backend) ListInstances(ctx context.Context, name, group string) ([]cfgov.ServiceInstance, error) {
	if err := validateServiceName(name); err != nil {
		return nil, err
	}
	if group != "" {
		if err := validatePart("group", group); err != nil {
			return nil, err
		}
	}
	instances, err := b.healthService(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]cfgov.ServiceInstance, 0, len(instances))
	for _, item := range instances {
		if item == nil || item.Service == nil {
			continue
		}
		if group != "" && item.Service.Meta["group"] != group {
			continue
		}
		out = append(out, serviceInstanceFromHealth(item))
	}
	return out, nil
}

func (b *Backend) RegisterInstance(ctx context.Context, service, ip string, port int, opts cfgov.InstanceOptions) error {
	if err := validateServiceMutation(service, ip, port, opts); err != nil {
		return err
	}
	if b.agent == nil {
		return apperrors.New(apperrors.CodeBackendUnreachable, "consul agent client not configured", nil)
	}
	req := &capi.AgentServiceRegistration{
		ID:      consulServiceID(service, ip, port),
		Name:    service,
		Address: ip,
		Port:    port,
		Meta:    consulServiceMeta(opts),
	}
	if opts.Weight > 0 {
		req.Weights = &capi.AgentWeights{Passing: int(opts.Weight), Warning: int(opts.Weight)}
	}
	return backendErr("consul register service failed", b.agent.ServiceRegisterOpts(req, capi.ServiceRegisterOpts{Token: b.token}.WithContext(ctx)))
}

func (b *Backend) DeregisterInstance(ctx context.Context, service, ip string, port int, opts cfgov.InstanceOptions) error {
	if err := validateServiceMutation(service, ip, port, opts); err != nil {
		return err
	}
	if b.agent == nil {
		return apperrors.New(apperrors.CodeBackendUnreachable, "consul agent client not configured", nil)
	}
	return backendErr("consul deregister service failed", b.agent.ServiceDeregisterOpts(consulServiceID(service, ip, port), b.queryOptions(ctx)))
}

func (b *Backend) catalogService(ctx context.Context, name string) ([]*capi.CatalogService, error) {
	if b.catalog == nil {
		return nil, apperrors.New(apperrors.CodeBackendUnreachable, "consul catalog client not configured", nil)
	}
	items, _, err := b.catalog.Service(name, "", b.queryOptions(ctx))
	if err != nil {
		return nil, backendErr("consul get service failed", err)
	}
	return items, nil
}

func (b *Backend) healthService(ctx context.Context, name string) ([]*capi.ServiceEntry, error) {
	if b.health == nil {
		return nil, apperrors.New(apperrors.CodeBackendUnreachable, "consul health client not configured", nil)
	}
	items, _, err := b.health.Service(name, "", false, b.queryOptions(ctx))
	if err != nil {
		return nil, backendErr("consul list service instances failed", err)
	}
	return items, nil
}

func (b *Backend) resolve(coord cfgov.Coordinate) (string, string, string, error) {
	ns := coord.Namespace
	if ns == "" {
		ns = b.namespace
	}
	if err := validatePart("namespace", ns); err != nil {
		return "", "", "", err
	}
	if err := validatePart("key", coord.Key); err != nil {
		return "", "", "", err
	}
	return ns, coord.Key, b.namespacePrefix(ns) + coord.Key, nil
}

func (b *Backend) namespacePrefix(namespace string) string {
	return b.keyPrefix + namespace + "/"
}

func (b *Backend) listItemFromPair(namespace, prefix string, pair *capi.KVPair, opts cfgov.ListOptions) (cfgov.ListItem, bool) {
	if pair == nil || !strings.HasPrefix(pair.Key, prefix) {
		return cfgov.ListItem{}, false
	}
	key := strings.TrimPrefix(pair.Key, prefix)
	if err := b.ValidateKey(key); err != nil {
		return cfgov.ListItem{}, false
	}
	if opts.Query != "" && key != opts.Query {
		return cfgov.ListItem{}, false
	}
	if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
		return cfgov.ListItem{}, false
	}
	return cfgov.ListItem{Coordinate: cfgov.Coordinate{Namespace: namespace, Key: key}, Revision: revisionString(pair.ModifyIndex), Type: "text"}, true
}

func blobFromPair(namespace, key string, pair *capi.KVPair) cfgov.Blob {
	return cfgov.Blob{
		Coordinate: cfgov.Coordinate{Namespace: namespace, Key: key},
		Content:    append([]byte(nil), pair.Value...),
		Revision:   revisionString(pair.ModifyIndex),
	}
}

func (b *Backend) queryOptions(ctx context.Context) *capi.QueryOptions {
	return (&capi.QueryOptions{Token: b.token}).WithContext(ctx)
}

func (b *Backend) writeOptions(ctx context.Context) *capi.WriteOptions {
	return (&capi.WriteOptions{Token: b.token}).WithContext(ctx)
}

func normalizeServer(raw string) (string, *url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil, apperrors.New(apperrors.CodeUsageError, "consul server address not specified", nil)
	}
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return "", nil, apperrors.New(apperrors.CodeValidationFailed, "consul server contains invalid control characters", nil)
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", nil, apperrors.New(apperrors.CodeUsageError, "invalid Consul server URL", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", nil, apperrors.New(apperrors.CodeUsageError, "Consul server URL must use http or https", nil)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return "", nil, apperrors.New(apperrors.CodeUsageError, "Consul server URL must not include credentials, path, query, or fragment", nil)
	}
	return parsed.Scheme + "://" + parsed.Host, parsed, nil
}

func normalizeKeyPrefix(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "\x00\r\n\t\\") {
		return "", apperrors.New(apperrors.CodeValidationFailed, "keyPrefix contains invalid path characters", nil)
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return "", apperrors.New(apperrors.CodeValidationFailed, "keyPrefix contains invalid path characters", nil)
		}
	}
	return strings.TrimRight(value, "/") + "/", nil
}

func validatePart(name, value string) error {
	if value == "" {
		return apperrors.New(apperrors.CodeUsageError, name+" is required", nil)
	}
	if value != strings.TrimSpace(value) {
		return apperrors.New(apperrors.CodeValidationFailed, name+" contains leading or trailing whitespace", nil)
	}
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return apperrors.New(apperrors.CodeValidationFailed, name+" contains invalid control characters", nil)
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return apperrors.New(apperrors.CodeValidationFailed, name+" contains invalid path characters", nil)
	}
	return nil
}

func validateServiceName(name string) error {
	return validatePart("service", name)
}

func validateServiceMutation(service, ip string, port int, opts cfgov.InstanceOptions) error {
	if err := validateServiceName(service); err != nil {
		return err
	}
	if net.ParseIP(ip) == nil || ip != strings.TrimSpace(ip) || strings.ContainsAny(ip, "\x00\r\n\t") {
		return apperrors.New(apperrors.CodeUsageError, "invalid instance IP", nil)
	}
	if port <= 0 || port > 65535 {
		return apperrors.New(apperrors.CodeUsageError, "port must be between 1 and 65535", nil)
	}
	if opts.GroupName != "" {
		if err := validatePart("group", opts.GroupName); err != nil {
			return err
		}
	}
	if opts.Cluster != "" {
		if err := validatePart("cluster", opts.Cluster); err != nil {
			return err
		}
	}
	for key, value := range opts.Metadata {
		if err := validatePart("metadata key", key); err != nil {
			return err
		}
		if strings.ContainsAny(value, "\x00\r\n\t") {
			return apperrors.New(apperrors.CodeValidationFailed, "metadata value contains invalid control characters", nil)
		}
	}
	if opts.Weight < 0 {
		return apperrors.New(apperrors.CodeUsageError, "weight must be non-negative", nil)
	}
	return nil
}

func consulServiceID(service, ip string, port int) string {
	return service + "-" + ip + "-" + strconv.Itoa(port)
}

func consulServiceMeta(opts cfgov.InstanceOptions) map[string]string {
	if len(opts.Metadata) == 0 && opts.GroupName == "" && opts.Cluster == "" && opts.Ephemeral == nil {
		return nil
	}
	meta := make(map[string]string, len(opts.Metadata)+3)
	for key, value := range opts.Metadata {
		meta[key] = value
	}
	// Consul has no Nacos group/cluster/ephemeral equivalents. Preserve these
	// user-supplied knobs as service metadata instead of pretending they are
	// native Consul fields.
	if opts.GroupName != "" {
		meta["group"] = opts.GroupName
	}
	if opts.Cluster != "" {
		meta["cluster"] = opts.Cluster
	}
	if opts.Ephemeral != nil {
		meta["ephemeral"] = strconv.FormatBool(*opts.Ephemeral)
	}
	return meta
}

func serviceInstanceFromHealth(entry *capi.ServiceEntry) cfgov.ServiceInstance {
	if entry == nil || entry.Service == nil {
		return cfgov.ServiceInstance{}
	}
	service := entry.Service
	ip := service.Address
	if ip == "" && entry.Node != nil {
		ip = entry.Node.Address
	}
	meta := map[string]string(nil)
	if len(service.Meta) > 0 {
		meta = make(map[string]string, len(service.Meta))
		for key, value := range service.Meta {
			meta[key] = value
		}
	}
	return cfgov.ServiceInstance{
		IP:       ip,
		Port:     service.DefaultPort(),
		Healthy:  entry.Checks.AggregatedStatus() == capi.HealthPassing,
		Enabled:  true,
		Weight:   float64(service.Weights.Passing),
		Metadata: meta,
	}
}

func paginateNames(names []string, page, pageSize int) []string {
	if page <= 0 || pageSize <= 0 {
		return names
	}
	start := (page - 1) * pageSize
	if start >= len(names) {
		return nil
	}
	end := start + pageSize
	if end > len(names) {
		end = len(names)
	}
	return names[start:end]
}

func parseRevision(value string) (uint64, error) {
	rev, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, apperrors.New(apperrors.CodeValidationFailed, "invalid Consul revision", err)
	}
	return rev, nil
}

func revisionString(rev uint64) string {
	if rev == 0 {
		return ""
	}
	return strconv.FormatUint(rev, 10)
}

func backendErr(message string, err error) error {
	if err == nil {
		return nil
	}
	return apperrors.New(apperrors.CodeBackendError, message, err)
}

func (b *Backend) tracef(format string, args ...any) {
	if !b.trace {
		return
	}
	_, _ = fmt.Fprintf(b.traceOut, format, args...)
}

func redactKey(key string) string {
	return fmt.Sprintf("<key:%d>", len(key))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
