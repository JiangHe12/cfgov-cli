// Package etcd adapts etcd v3 KV to cfgov.Backend.
//
// Coordinate mapping:
//   - Backend options carry etcd endpoints, a key prefix, and a default namespace.
//   - cfgov.Coordinate.Namespace maps to one etcd path segment under keyPrefix.
//   - cfgov.Coordinate.Key maps to one etcd path segment under that namespace.
//   - The full etcd key is "<keyPrefix><namespace>/<key>".
//
// Rule coordinate mapping:
//   - RuleCoordinate(app, type) maps to Coordinate{Namespace: ruleNamespace,
//     Key: "{app}-{type}-rules"}.
//   - ruleNamespace defaults to "SENTINEL" and is intentionally separate from
//     the config namespace default "application".
//
// History, namespace, and service operations are not supported by etcd here.
package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

const (
	defaultNamespace     = "application"
	defaultRuleNamespace = "SENTINEL"
)

type Options struct {
	Endpoints     string
	KeyPrefix     string
	Namespace     string
	RuleNamespace string
	Username      string
	Password      string
	CACert        string
	ClientCert    string
	ClientKey     string
	Timeout       time.Duration
	Trace         bool
	TraceOut      io.Writer

	client etcdClient
}

type Backend struct {
	endpoints     []string
	server        string
	keyPrefix     string
	namespace     string
	ruleNamespace string
	client        etcdClient
	close         func() error
	trace         bool
	traceOut      io.Writer
}

type etcdClient interface {
	Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
	Put(ctx context.Context, key, val string, opts ...clientv3.OpOption) (*clientv3.PutResponse, error)
	Delete(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.DeleteResponse, error)
	Txn(ctx context.Context) clientv3.Txn
	Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan
}

var (
	_ cfgov.Backend   = (*Backend)(nil)
	_ cfgov.RuleStore = (*Backend)(nil)
)

func ValidateEndpoints(raw string) error {
	_, err := normalizeEndpoints(raw)
	return err
}

func ValidateKeyPrefix(raw string) error {
	_, err := normalizeKeyPrefix(raw)
	return err
}

func New(opts Options) (*Backend, error) {
	endpoints, err := normalizeEndpoints(opts.Endpoints)
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
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	out := opts.TraceOut
	if out == nil {
		out = os.Stderr
	}
	tlsConfig, err := loadTLSConfig(opts.CACert, opts.ClientCert, opts.ClientKey)
	if err != nil {
		return nil, err
	}
	client := opts.client
	var closeFn func() error
	if client == nil {
		realClient, err := clientv3.New(clientv3.Config{
			Endpoints:   endpoints,
			DialTimeout: timeout,
			Username:    opts.Username,
			Password:    opts.Password,
			TLS:         tlsConfig,
		})
		if err != nil {
			return nil, apperrors.New(apperrors.CodeBackendUnreachable, "failed to create etcd client", err)
		}
		client = realClient
		closeFn = realClient.Close
	}
	return &Backend{
		endpoints:     endpoints,
		server:        strings.Join(endpoints, ","),
		keyPrefix:     keyPrefix,
		namespace:     namespace,
		ruleNamespace: ruleNamespace,
		client:        client,
		close:         closeFn,
		trace:         opts.Trace,
		traceOut:      out,
	}, nil
}

func (b *Backend) ValidateKey(key string) error {
	return validatePart("key", key)
}

func (b *Backend) Get(ctx context.Context, coord cfgov.Coordinate) (cfgov.Blob, error) {
	ns, key, fullKey, err := b.resolve(coord)
	if err != nil {
		return cfgov.Blob{}, err
	}
	b.tracef("[trace] >>> etcd get %s\n", redactKey(fullKey))
	resp, err := b.client.Get(ctx, fullKey)
	if err != nil {
		return cfgov.Blob{}, backendErr("etcd get failed", err)
	}
	if len(resp.Kvs) == 0 {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeResourceNotFound, "etcd key not found", nil)
	}
	kv := resp.Kvs[0]
	return cfgov.Blob{Coordinate: cfgov.Coordinate{Namespace: ns, Key: key}, Content: append([]byte(nil), kv.Value...), Revision: revisionString(kv.ModRevision)}, nil
}

func (b *Backend) Put(ctx context.Context, req cfgov.PutRequest) (cfgov.Blob, error) {
	ns, key, fullKey, err := b.resolve(req.Coordinate)
	if err != nil {
		return cfgov.Blob{}, err
	}
	if req.ExpectedRevision != "" {
		rev, err := parseRevision(req.ExpectedRevision)
		if err != nil {
			return cfgov.Blob{}, err
		}
		b.tracef("[trace] >>> etcd txn put %s\n", redactKey(fullKey))
		resp, err := b.client.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(fullKey), "=", rev)).
			Then(clientv3.OpPut(fullKey, string(req.Content))).
			Else().
			Commit()
		if err != nil {
			return cfgov.Blob{}, backendErr("etcd put failed", err)
		}
		if !resp.Succeeded {
			return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
		}
		return b.Get(ctx, cfgov.Coordinate{Namespace: ns, Key: key})
	}
	b.tracef("[trace] >>> etcd put %s\n", redactKey(fullKey))
	if _, err := b.client.Put(ctx, fullKey, string(req.Content)); err != nil {
		return cfgov.Blob{}, backendErr("etcd put failed", err)
	}
	return b.Get(ctx, cfgov.Coordinate{Namespace: ns, Key: key})
}

func (b *Backend) Delete(ctx context.Context, req cfgov.DeleteRequest) error {
	_, _, fullKey, err := b.resolve(req.Coordinate)
	if err != nil {
		return err
	}
	if req.ExpectedRevision != "" {
		rev, err := parseRevision(req.ExpectedRevision)
		if err != nil {
			return err
		}
		b.tracef("[trace] >>> etcd txn delete %s\n", redactKey(fullKey))
		resp, err := b.client.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(fullKey), "=", rev)).
			Then(clientv3.OpDelete(fullKey)).
			Else().
			Commit()
		if err != nil {
			return backendErr("etcd delete failed", err)
		}
		if !resp.Succeeded {
			return apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
		}
		return nil
	}
	b.tracef("[trace] >>> etcd delete %s\n", redactKey(fullKey))
	if _, err := b.client.Delete(ctx, fullKey); err != nil {
		return backendErr("etcd delete failed", err)
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
	prefix := b.namespacePrefix(ns)
	b.tracef("[trace] >>> etcd list %s\n", redactKey(prefix))
	resp, err := b.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, backendErr("etcd list failed", err)
	}
	out := make([]cfgov.ListItem, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		item, ok := b.listItemFromKV(ns, prefix, kv, opts)
		if !ok {
			continue
		}
		out = append(out, item)
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Coordinate.Key < out[j].Coordinate.Key })
	return out, nil
}

func (b *Backend) History(context.Context, cfgov.Coordinate, cfgov.HistoryOptions) ([]cfgov.HistoryItem, int, error) {
	return nil, 0, apperrors.New(apperrors.CodeNotImplemented, "etcd backend does not support config history", nil)
}

func (b *Backend) Watch(ctx context.Context, coord cfgov.Coordinate, revision string, opts cfgov.WatchOptions) (cfgov.WatchEvent, error) {
	ns, key, fullKey, err := b.resolve(coord)
	if err != nil {
		return cfgov.WatchEvent{}, err
	}
	watchCtx := ctx
	cancel := func() {}
	if opts.LongPoll > 0 {
		watchCtx, cancel = context.WithTimeout(ctx, opts.LongPoll)
	}
	defer cancel()
	watchOpts := []clientv3.OpOption{}
	if revision != "" {
		rev, err := parseRevision(revision)
		if err != nil {
			return cfgov.WatchEvent{}, err
		}
		watchOpts = append(watchOpts, clientv3.WithRev(rev+1))
	}
	b.tracef("[trace] >>> etcd watch %s\n", redactKey(fullKey))
	ch := b.client.Watch(watchCtx, fullKey, watchOpts...)
	select {
	case resp, ok := <-ch:
		if !ok {
			if err := watchCtx.Err(); err != nil {
				return cfgov.WatchEvent{Coordinate: cfgov.Coordinate{Namespace: ns, Key: key}, Revision: revision, Changed: false}, nil
			}
			return cfgov.WatchEvent{}, apperrors.New(apperrors.CodeBackendError, "etcd watch closed", nil)
		}
		if err := resp.Err(); err != nil {
			return cfgov.WatchEvent{}, backendErr("etcd watch failed", err)
		}
		if len(resp.Events) == 0 {
			return cfgov.WatchEvent{Coordinate: cfgov.Coordinate{Namespace: ns, Key: key}, Revision: revision, Changed: false}, nil
		}
		return cfgov.WatchEvent{Coordinate: cfgov.Coordinate{Namespace: ns, Key: key}, Revision: eventRevision(resp.Events[len(resp.Events)-1]), Changed: true}, nil
	case <-watchCtx.Done():
		return cfgov.WatchEvent{Coordinate: cfgov.Coordinate{Namespace: ns, Key: key}, Revision: revision, Changed: false}, nil
	}
}

func (b *Backend) CurrentRevision(ctx context.Context, coord cfgov.Coordinate) (string, error) {
	blob, err := b.Get(ctx, coord)
	if err != nil {
		return "", err
	}
	return blob.Revision, nil
}

func (b *Backend) Ping(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := b.client.Get(pingCtx, b.keyPrefix, clientv3.WithPrefix(), clientv3.WithLimit(1))
	if err != nil {
		return backendErr("etcd ping failed", err)
	}
	return nil
}

func (b *Backend) Describe() cfgov.Description {
	return cfgov.Description{Backend: "etcd", Server: b.server, Namespace: b.namespace}
}

func (b *Backend) Capabilities() cfgov.Capabilities {
	return cfgov.Capabilities{
		Backend:          "etcd",
		ResourceTypes:    []string{"config", "rule"},
		Verbs:            []string{"get", "list", "diff", "validate", "pull", "listen", "push", "delete"},
		SupportsCAS:      true,
		SupportsRevision: true,
		SupportsHistory:  false,
		SupportsWatch:    true,
		SupportsRules:    true,
	}
}

func (b *Backend) RuleCoordinate(app, ruleType string) (cfgov.Coordinate, error) {
	parsed, err := rule.ParseType(ruleType)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	dataID, err := rule.DataID(app, parsed)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	if err := validatePart("rule namespace", b.ruleNamespace); err != nil {
		return cfgov.Coordinate{}, err
	}
	if err := validatePart("rule key", dataID); err != nil {
		return cfgov.Coordinate{}, err
	}
	return cfgov.Coordinate{Namespace: b.ruleNamespace, Key: dataID}, nil
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

func (b *Backend) listItemFromKV(namespace, prefix string, kv *mvccpb.KeyValue, opts cfgov.ListOptions) (cfgov.ListItem, bool) {
	rawKey := string(kv.Key)
	if !strings.HasPrefix(rawKey, prefix) {
		return cfgov.ListItem{}, false
	}
	key := strings.TrimPrefix(rawKey, prefix)
	if err := b.ValidateKey(key); err != nil {
		return cfgov.ListItem{}, false
	}
	if opts.Query != "" && key != opts.Query {
		return cfgov.ListItem{}, false
	}
	if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
		return cfgov.ListItem{}, false
	}
	return cfgov.ListItem{Coordinate: cfgov.Coordinate{Namespace: namespace, Key: key}, Revision: revisionString(kv.ModRevision), Type: "text"}, true
}

func (b *Backend) tracef(format string, args ...any) {
	if !b.trace {
		return
	}
	_, _ = fmt.Fprintf(b.traceOut, format, args...)
}

func normalizeEndpoints(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, apperrors.New(apperrors.CodeUsageError, "etcd endpoints not specified", nil)
	}
	parts := strings.Split(raw, ",")
	endpoints := make([]string, 0, len(parts))
	for _, part := range parts {
		endpoint, err := normalizeEndpoint(part)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func normalizeEndpoint(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", apperrors.New(apperrors.CodeUsageError, "empty etcd endpoint", nil)
	}
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return "", apperrors.New(apperrors.CodeValidationFailed, "etcd endpoint contains invalid control characters", nil)
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", apperrors.New(apperrors.CodeUsageError, "invalid etcd endpoint", err)
	}
	if err := validateEndpointURL(parsed); err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func validateEndpointURL(parsed *url.URL) error {
	if parsed.Scheme == "" || parsed.Host == "" {
		return apperrors.New(apperrors.CodeUsageError, "invalid etcd endpoint", nil)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return apperrors.New(apperrors.CodeUsageError, "etcd endpoint must use http or https", nil)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return apperrors.New(apperrors.CodeUsageError, "etcd endpoint must not include credentials, path, query, or fragment", nil)
	}
	if host := parsed.Hostname(); host == "" {
		return apperrors.New(apperrors.CodeUsageError, "invalid etcd endpoint host", nil)
	}
	if port := parsed.Port(); port != "" {
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			return apperrors.New(apperrors.CodeUsageError, "invalid etcd endpoint port", err)
		}
	}
	return nil
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
	value = strings.TrimSpace(value)
	if value == "" {
		return apperrors.New(apperrors.CodeUsageError, name+" is required", nil)
	}
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return apperrors.New(apperrors.CodeValidationFailed, name+" contains invalid control characters", nil)
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return apperrors.New(apperrors.CodeValidationFailed, name+" contains invalid path characters", nil)
	}
	return nil
}

func loadTLSConfig(caCert, clientCert, clientKey string) (*tls.Config, error) {
	if caCert == "" && clientCert == "" && clientKey == "" {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caCert != "" {
		data, err := os.ReadFile(caCert) //nolint:gosec // Operator supplied CA path for TLS trust.
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read etcd CA certificate", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "failed to parse etcd CA certificate", nil)
		}
		cfg.RootCAs = pool
	}
	if clientCert != "" || clientKey != "" {
		if clientCert == "" || clientKey == "" {
			return nil, apperrors.New(apperrors.CodeUsageError, "both etcd client certificate and client key are required for mTLS", nil)
		}
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "failed to load etcd client certificate/key", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func parseRevision(value string) (int64, error) {
	rev, err := strconv.ParseInt(value, 10, 64)
	if err != nil || rev < 0 {
		return 0, apperrors.New(apperrors.CodeValidationFailed, "invalid etcd revision", err)
	}
	return rev, nil
}

func revisionString(rev int64) string {
	if rev <= 0 {
		return ""
	}
	return strconv.FormatInt(rev, 10)
}

func eventRevision(event *clientv3.Event) string {
	if event == nil || event.Kv == nil {
		return ""
	}
	return revisionString(event.Kv.ModRevision)
}

func backendErr(message string, err error) error {
	if err == nil {
		return nil
	}
	return apperrors.New(apperrors.CodeBackendError, message, err)
}

func redactKey(key string) string {
	if key == "" {
		return ""
	}
	return "<key:" + strconv.Itoa(len(key)) + ">"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
