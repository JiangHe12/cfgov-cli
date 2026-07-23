// Package k8s adapts Kubernetes ConfigMaps and Secrets to cfgov.Backend.
//
// Coordinate mapping:
//   - cfgov.Coordinate.Namespace maps to a Kubernetes namespace.
//   - cfgov.Coordinate.Key maps to exactly "<kind>/<name>/<dataKey>".
//   - kind is either "configmap" or "secret".
//
// Rule coordinate mapping:
//   - RuleCoordinate(app, type) maps to Coordinate{Namespace: backend namespace,
//     Key: "configmap/{app}-{type}-rules/rules.json"}.
//
// History is not supported here.
package k8s

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	apiwatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/redact"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

const (
	defaultNamespace = "default"
	kindConfigMap    = "configmap"
	kindSecret       = "secret"
	ruleDataKey      = "rules.json"
)

type Options struct {
	Kubeconfig string
	Context    string
	Namespace  string
	Timeout    time.Duration
	Trace      bool
	TraceOut   io.Writer

	client kubernetes.Interface
}

type Backend struct {
	kubeconfig string
	context    string
	namespace  string
	client     kubernetes.Interface
	trace      bool
	traceOut   io.Writer
}

type coordinate struct {
	Namespace string
	Kind      string
	Name      string
	DataKey   string
}

type typedConfigMapClient interface {
	Update(ctx context.Context, configMap *corev1.ConfigMap, opts metav1.UpdateOptions) (*corev1.ConfigMap, error)
}

type typedSecretClient interface {
	Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error)
}

var (
	_ cfgov.Backend   = (*Backend)(nil)
	_ cfgov.RuleStore = (*Backend)(nil)
	_ cfgov.FlagStore = (*Backend)(nil)
)

func init() {
	// client-go has a small number of process-global klog paths (notably exec
	// credential refresh) that cannot be routed through a per-client writer.
	// Suppress those here; cfgov emits its own redacted warnings and traces.
	klog.SetLogger(logr.Discard())
}

func New(opts Options) (*Backend, error) {
	namespace := firstNonEmpty(opts.Namespace, defaultNamespace)
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	out := opts.TraceOut
	if out == nil {
		out = os.Stderr
	}
	client := opts.client
	if client == nil {
		config, err := buildRESTConfig(opts.Kubeconfig, opts.Context, opts.Timeout)
		if err != nil {
			return nil, err
		}
		config.WarningHandlerWithContext = redactedWarningHandler{out: out}
		client, err = kubernetes.NewForConfig(config)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeBackendError, "failed to create Kubernetes client", err)
		}
	}
	return &Backend{
		kubeconfig: firstNonEmpty(opts.Kubeconfig, os.Getenv("KUBECONFIG"), defaultKubeconfigPath()),
		context:    opts.Context,
		namespace:  namespace,
		client:     client,
		trace:      opts.Trace,
		traceOut:   out,
	}, nil
}

type redactedWarningHandler struct {
	out io.Writer
}

func (handler redactedWarningHandler) HandleWarningHeaderWithContext(_ context.Context, code int, _ string, message string) {
	if code != 299 || message == "" {
		return
	}
	_, _ = fmt.Fprintf(handler.out, "warning: kubernetes API: %s\n", redact.String(message))
}

func (b *Backend) ValidateKey(key string) error {
	_, err := parseKey(key)
	return err
}

func (b *Backend) Get(ctx context.Context, coord cfgov.Coordinate) (cfgov.Blob, error) {
	resolved, err := b.resolve(coord)
	if err != nil {
		return cfgov.Blob{}, err
	}
	b.tracef("[trace] >>> k8s get %s\n", redactRef(resolved, 0))
	switch resolved.Kind {
	case kindConfigMap:
		return b.getConfigMap(ctx, resolved)
	case kindSecret:
		return b.getSecret(ctx, resolved)
	default:
		return cfgov.Blob{}, apperrors.New(apperrors.CodeValidationFailed, "unsupported Kubernetes config kind", nil)
	}
}

func (b *Backend) Put(ctx context.Context, req cfgov.PutRequest) (cfgov.Blob, error) {
	if err := req.ValidatePreconditions(); err != nil {
		return cfgov.Blob{}, err
	}
	resolved, err := b.resolve(req.Coordinate)
	if err != nil {
		return cfgov.Blob{}, err
	}
	b.tracef("[trace] >>> k8s put %s\n", redactRef(resolved, len(req.Content)))
	switch resolved.Kind {
	case kindConfigMap:
		return b.putConfigMap(ctx, resolved, req)
	case kindSecret:
		return b.putSecret(ctx, resolved, req)
	default:
		return cfgov.Blob{}, apperrors.New(apperrors.CodeValidationFailed, "unsupported Kubernetes config kind", nil)
	}
}

func (b *Backend) Delete(ctx context.Context, req cfgov.DeleteRequest) error {
	resolved, err := b.resolve(req.Coordinate)
	if err != nil {
		return err
	}
	b.tracef("[trace] >>> k8s delete %s\n", redactRef(resolved, 0))
	switch resolved.Kind {
	case kindConfigMap:
		return b.deleteConfigMap(ctx, resolved, req.ExpectedRevision)
	case kindSecret:
		return b.deleteSecret(ctx, resolved, req.ExpectedRevision)
	default:
		return apperrors.New(apperrors.CodeValidationFailed, "unsupported Kubernetes config kind", nil)
	}
}

func (b *Backend) List(ctx context.Context, opts cfgov.ListOptions) ([]cfgov.ListItem, error) {
	namespace := opts.Namespace
	if namespace == "" {
		namespace = b.namespace
	}
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	if opts.Query != "" {
		if err := b.ValidateKey(opts.Query); err != nil {
			return nil, err
		}
	}
	if err := validatePrefix(opts.Prefix); err != nil {
		return nil, err
	}
	b.tracef("[trace] >>> k8s list namespace=%s prefix=%s\n", namespace, redactPrefix(opts.Prefix))
	out := []cfgov.ListItem{}
	configMaps, err := b.client.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, backendErr("k8s list configmaps failed", err)
	}
	out = appendConfigMapListItems(out, namespace, configMaps.Items, opts)
	secrets, err := b.client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, backendErr("k8s list secrets failed", err)
	}
	out = appendSecretListItems(out, namespace, secrets.Items, opts)
	sort.Slice(out, func(i, j int) bool { return out[i].Coordinate.Key < out[j].Coordinate.Key })
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}

func (b *Backend) History(context.Context, cfgov.Coordinate, cfgov.HistoryOptions) ([]cfgov.HistoryItem, int, error) {
	return nil, 0, apperrors.New(apperrors.CodeNotImplemented, "k8s backend does not support config history", nil)
}

func (b *Backend) Watch(ctx context.Context, coord cfgov.Coordinate, revision string, opts cfgov.WatchOptions) (cfgov.WatchEvent, error) {
	resolved, err := b.resolve(coord)
	if err != nil {
		return cfgov.WatchEvent{}, err
	}
	watchCtx := ctx
	cancel := func() {}
	if opts.LongPoll > 0 {
		watchCtx, cancel = context.WithTimeout(ctx, opts.LongPoll)
	}
	defer cancel()
	// Kubernetes watches are object-granular: any data key change on the
	// ConfigMap/Secret can trigger this watch, even when coord targets one key.
	listOpts := metav1.ListOptions{
		FieldSelector:   "metadata.name=" + resolved.Name,
		ResourceVersion: revision,
	}
	b.tracef("[trace] >>> k8s watch %s\n", redactRef(resolved, 0))
	var watcher apiwatch.Interface
	switch resolved.Kind {
	case kindConfigMap:
		watcher, err = b.client.CoreV1().ConfigMaps(resolved.Namespace).Watch(watchCtx, listOpts)
	case kindSecret:
		watcher, err = b.client.CoreV1().Secrets(resolved.Namespace).Watch(watchCtx, listOpts)
	default:
		return cfgov.WatchEvent{}, apperrors.New(apperrors.CodeValidationFailed, "unsupported Kubernetes config kind", nil)
	}
	if err != nil {
		return cfgov.WatchEvent{}, backendErr("k8s watch failed", err)
	}
	defer watcher.Stop()
	result := watcher.ResultChan()
	select {
	case event, ok := <-result:
		if !ok {
			return cfgov.WatchEvent{Coordinate: resolved.coord(), Revision: revision, Changed: false}, nil
		}
		nextRevision := objectRevision(event.Object)
		if nextRevision == "" {
			nextRevision = revision
		}
		switch event.Type {
		case apiwatch.Added, apiwatch.Modified, apiwatch.Deleted:
			return cfgov.WatchEvent{Coordinate: resolved.coord(), Revision: nextRevision, Changed: true}, nil
		case apiwatch.Error:
			return cfgov.WatchEvent{}, apperrors.New(apperrors.CodeBackendError, "k8s watch failed", nil)
		case apiwatch.Bookmark:
			return cfgov.WatchEvent{Coordinate: resolved.coord(), Revision: revision, Changed: false}, nil
		default:
			return cfgov.WatchEvent{Coordinate: resolved.coord(), Revision: revision, Changed: false}, nil
		}
	case <-watchCtx.Done():
		return cfgov.WatchEvent{Coordinate: resolved.coord(), Revision: revision, Changed: false}, nil
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
	_, err := b.client.CoreV1().ConfigMaps(b.namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return backendErr("k8s ping failed", err)
	}
	return nil
}

func (b *Backend) Describe() cfgov.Description {
	return cfgov.Description{Backend: "k8s", Server: b.context, Namespace: b.namespace}
}

func (b *Backend) Capabilities() cfgov.Capabilities {
	return cfgov.Capabilities{
		Backend:          "k8s",
		ResourceTypes:    []string{"config", "rule", "flag"},
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
	parsed, err := rule.ParseType(ruleType)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	dataID, err := rule.DataID(app, parsed)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	key := kindConfigMap + "/" + dataID + "/" + ruleDataKey
	if _, err := parseKey(key); err != nil {
		return cfgov.Coordinate{}, err
	}
	return cfgov.Coordinate{Namespace: b.namespace, Key: key}, nil
}

func (b *Backend) FlagCoordinate(app string) (cfgov.Coordinate, error) {
	dataID, err := flag.DataID(app)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	key := kindConfigMap + "/" + dataID + "/flags.json"
	if _, err := parseKey(key); err != nil {
		return cfgov.Coordinate{}, err
	}
	return cfgov.Coordinate{Namespace: b.namespace, Key: key}, nil
}

func (b *Backend) getConfigMap(ctx context.Context, resolved coordinate) (cfgov.Blob, error) {
	item, err := b.client.CoreV1().ConfigMaps(resolved.Namespace).Get(ctx, resolved.Name, metav1.GetOptions{})
	if err != nil {
		return cfgov.Blob{}, backendErr("k8s get configmap failed", err)
	}
	value, ok := item.Data[resolved.DataKey]
	if !ok {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeResourceNotFound, "configmap data key not found", nil)
	}
	return cfgov.Blob{Coordinate: resolved.coord(), Content: []byte(value), Revision: item.ResourceVersion}, nil
}

func (b *Backend) getSecret(ctx context.Context, resolved coordinate) (cfgov.Blob, error) {
	item, err := b.client.CoreV1().Secrets(resolved.Namespace).Get(ctx, resolved.Name, metav1.GetOptions{})
	if err != nil {
		return cfgov.Blob{}, backendErr("k8s get secret failed", err)
	}
	value, ok := item.Data[resolved.DataKey]
	if !ok {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeResourceNotFound, "secret data key not found", nil)
	}
	return cfgov.Blob{Coordinate: resolved.coord(), Content: append([]byte(nil), value...), Revision: item.ResourceVersion}, nil
}

func (b *Backend) putConfigMap(ctx context.Context, resolved coordinate, req cfgov.PutRequest) (cfgov.Blob, error) {
	client := b.client.CoreV1().ConfigMaps(resolved.Namespace)
	item, err := client.Get(ctx, resolved.Name, metav1.GetOptions{})
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return cfgov.Blob{}, backendErr("k8s get configmap failed", err)
		}
		if req.ExpectedRevision != "" {
			return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
		}
		created, err := client.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: resolved.Name, Namespace: resolved.Namespace},
			Data:       map[string]string{resolved.DataKey: string(req.Content)},
		}, metav1.CreateOptions{})
		if err != nil {
			return cfgov.Blob{}, backendErr("k8s create configmap failed", err)
		}
		return cfgov.Blob{Coordinate: resolved.coord(), Content: append([]byte(nil), req.Content...), Revision: created.ResourceVersion}, nil
	}
	if req.RequireAbsent {
		if _, exists := item.Data[resolved.DataKey]; exists {
			return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config precondition failed", nil)
		}
	} else {
		if err := checkRevision(item.ResourceVersion, req.ExpectedRevision); err != nil {
			return cfgov.Blob{}, err
		}
	}
	if item.Data == nil {
		item.Data = map[string]string{}
	}
	item.Data[resolved.DataKey] = string(req.Content)
	updated, err := client.Update(ctx, item, metav1.UpdateOptions{})
	if err != nil {
		return cfgov.Blob{}, backendErr("k8s update configmap failed", err)
	}
	return cfgov.Blob{Coordinate: resolved.coord(), Content: append([]byte(nil), req.Content...), Revision: updated.ResourceVersion}, nil
}

func (b *Backend) putSecret(ctx context.Context, resolved coordinate, req cfgov.PutRequest) (cfgov.Blob, error) {
	client := b.client.CoreV1().Secrets(resolved.Namespace)
	item, err := client.Get(ctx, resolved.Name, metav1.GetOptions{})
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return cfgov.Blob{}, backendErr("k8s get secret failed", err)
		}
		if req.ExpectedRevision != "" {
			return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
		}
		created, err := client.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: resolved.Name, Namespace: resolved.Namespace},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{resolved.DataKey: append([]byte(nil), req.Content...)},
		}, metav1.CreateOptions{})
		if err != nil {
			return cfgov.Blob{}, backendErr("k8s create secret failed", err)
		}
		return cfgov.Blob{Coordinate: resolved.coord(), Content: append([]byte(nil), req.Content...), Revision: created.ResourceVersion}, nil
	}
	if req.RequireAbsent {
		if _, exists := item.Data[resolved.DataKey]; exists {
			return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config precondition failed", nil)
		}
	} else {
		if err := checkRevision(item.ResourceVersion, req.ExpectedRevision); err != nil {
			return cfgov.Blob{}, err
		}
	}
	if item.Type == "" {
		item.Type = corev1.SecretTypeOpaque
	}
	if item.Data == nil {
		item.Data = map[string][]byte{}
	}
	item.Data[resolved.DataKey] = append([]byte(nil), req.Content...)
	updated, err := client.Update(ctx, item, metav1.UpdateOptions{})
	if err != nil {
		return cfgov.Blob{}, backendErr("k8s update secret failed", err)
	}
	return cfgov.Blob{Coordinate: resolved.coord(), Content: append([]byte(nil), req.Content...), Revision: updated.ResourceVersion}, nil
}

func (b *Backend) deleteConfigMap(ctx context.Context, resolved coordinate, expectedRevision string) error {
	client := b.client.CoreV1().ConfigMaps(resolved.Namespace)
	item, err := client.Get(ctx, resolved.Name, metav1.GetOptions{})
	if err != nil {
		return backendErr("k8s get configmap failed", err)
	}
	return updateConfigMapAfterDelete(ctx, client, item, resolved.DataKey, expectedRevision)
}

func updateConfigMapAfterDelete(ctx context.Context, client typedConfigMapClient, item *corev1.ConfigMap, dataKey, expectedRevision string) error {
	if err := checkRevision(item.ResourceVersion, expectedRevision); err != nil {
		return err
	}
	if err := deleteDataKey(item.Data, dataKey, "configmap data key not found"); err != nil {
		return err
	}
	if _, err := client.Update(ctx, item, metav1.UpdateOptions{}); err != nil {
		return backendErr("k8s update configmap failed", err)
	}
	return nil
}

func (b *Backend) deleteSecret(ctx context.Context, resolved coordinate, expectedRevision string) error {
	client := b.client.CoreV1().Secrets(resolved.Namespace)
	item, err := client.Get(ctx, resolved.Name, metav1.GetOptions{})
	if err != nil {
		return backendErr("k8s get secret failed", err)
	}
	return updateSecretAfterDelete(ctx, client, item, resolved.DataKey, expectedRevision)
}

func updateSecretAfterDelete(ctx context.Context, client typedSecretClient, item *corev1.Secret, dataKey, expectedRevision string) error {
	if err := checkRevision(item.ResourceVersion, expectedRevision); err != nil {
		return err
	}
	if err := deleteDataKey(item.Data, dataKey, "secret data key not found"); err != nil {
		return err
	}
	if _, err := client.Update(ctx, item, metav1.UpdateOptions{}); err != nil {
		return backendErr("k8s update secret failed", err)
	}
	return nil
}

func (b *Backend) resolve(coord cfgov.Coordinate) (coordinate, error) {
	namespace := coord.Namespace
	if namespace == "" {
		namespace = b.namespace
	}
	if err := validateNamespace(namespace); err != nil {
		return coordinate{}, err
	}
	parsed, err := parseKey(coord.Key)
	if err != nil {
		return coordinate{}, err
	}
	parsed.Namespace = namespace
	return parsed, nil
}

func parseKey(key string) (coordinate, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return coordinate{}, apperrors.New(apperrors.CodeUsageError, "key is required", nil)
	}
	if strings.ContainsAny(key, "\x00\r\n\t\\") {
		return coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "key contains invalid path characters", nil)
	}
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "key must be <kind>/<name>/<dataKey>", nil)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "key contains invalid path segment", nil)
		}
	}
	kind, name, dataKey := parts[0], parts[1], parts[2]
	if kind != kindConfigMap && kind != kindSecret {
		return coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "key kind must be configmap or secret", nil)
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "Kubernetes object name is invalid", nil)
	}
	if errs := validation.IsConfigMapKey(dataKey); len(errs) > 0 {
		return coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "Kubernetes data key is invalid", nil)
	}
	return coordinate{Kind: kind, Name: name, DataKey: dataKey}, nil
}

func validateNamespace(namespace string) error {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return apperrors.New(apperrors.CodeUsageError, "namespace is required", nil)
	}
	if strings.ContainsAny(namespace, "\x00\r\n\t/\\") || namespace == "." || namespace == ".." {
		return apperrors.New(apperrors.CodeValidationFailed, "namespace contains invalid path characters", nil)
	}
	if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
		return apperrors.New(apperrors.CodeValidationFailed, "Kubernetes namespace is invalid", nil)
	}
	return nil
}

func validatePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if strings.ContainsAny(prefix, "\x00\r\n\t\\") {
		return apperrors.New(apperrors.CodeValidationFailed, "prefix contains invalid path characters", nil)
	}
	for _, part := range strings.Split(prefix, "/") {
		if part == "." || part == ".." {
			return apperrors.New(apperrors.CodeValidationFailed, "prefix contains invalid path segment", nil)
		}
	}
	return nil
}

func makeListItem(namespace, kind, name, dataKey, revision string, opts cfgov.ListOptions) (cfgov.ListItem, bool) {
	key := kind + "/" + name + "/" + dataKey
	if opts.Query != "" && key != opts.Query {
		return cfgov.ListItem{}, false
	}
	if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
		return cfgov.ListItem{}, false
	}
	return cfgov.ListItem{Coordinate: cfgov.Coordinate{Namespace: namespace, Key: key}, Revision: revision, Type: kind}, true
}

func appendConfigMapListItems(out []cfgov.ListItem, namespace string, items []corev1.ConfigMap, opts cfgov.ListOptions) []cfgov.ListItem {
	for _, item := range items {
		for dataKey := range item.Data {
			listItem, ok := makeListItem(namespace, kindConfigMap, item.Name, dataKey, item.ResourceVersion, opts)
			if ok {
				out = append(out, listItem)
			}
		}
	}
	return out
}

func appendSecretListItems(out []cfgov.ListItem, namespace string, items []corev1.Secret, opts cfgov.ListOptions) []cfgov.ListItem {
	for _, item := range items {
		for dataKey := range item.Data {
			listItem, ok := makeListItem(namespace, kindSecret, item.Name, dataKey, item.ResourceVersion, opts)
			if ok {
				out = append(out, listItem)
			}
		}
	}
	return out
}

func deleteDataKey[T any](data map[string]T, key, missingMessage string) error {
	if _, ok := data[key]; !ok {
		return apperrors.New(apperrors.CodeResourceNotFound, missingMessage, nil)
	}
	delete(data, key)
	return nil
}

func checkRevision(current, expected string) error {
	if expected != "" && current != expected {
		return apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
	}
	return nil
}

func objectRevision(obj any) string {
	switch item := obj.(type) {
	case *corev1.ConfigMap:
		return item.ResourceVersion
	case *corev1.Secret:
		return item.ResourceVersion
	default:
		return ""
	}
}

func backendErr(message string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case k8serrors.IsNotFound(err):
		return apperrors.New(apperrors.CodeResourceNotFound, message, err)
	case k8serrors.IsConflict(err), k8serrors.IsAlreadyExists(err):
		return apperrors.New(apperrors.CodeConflict, "config revision changed", err)
	default:
		return apperrors.New(apperrors.CodeBackendError, message, err)
	}
}

func buildRESTConfig(kubeconfig, contextName string, timeout time.Duration) (*rest.Config, error) {
	path := firstNonEmpty(kubeconfig, os.Getenv("KUBECONFIG"), defaultKubeconfigPath())
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	loadingConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	rawConfig, err := loadingConfig.RawConfig()
	if err != nil {
		return nil, apperrors.New(apperrors.CodeUsageError, "failed to load Kubernetes kubeconfig", err)
	}
	if err := rejectExecCredentialPlugin(rawConfig, contextName); err != nil {
		return nil, err
	}
	config, err := loadingConfig.ClientConfig()
	if err != nil {
		return nil, apperrors.New(apperrors.CodeUsageError, "failed to load Kubernetes kubeconfig", err)
	}
	if timeout > 0 {
		config.Timeout = timeout
	}
	return config, nil
}

func rejectExecCredentialPlugin(config clientcmdapi.Config, contextName string) error {
	selectedContext := contextName
	if selectedContext == "" {
		selectedContext = config.CurrentContext
	}
	contextConfig := config.Contexts[selectedContext]
	if contextConfig == nil {
		return nil
	}
	authInfo := config.AuthInfos[contextConfig.AuthInfo]
	if authInfo == nil || authInfo.Exec == nil {
		return nil
	}
	return apperrors.New(
		apperrors.CodeNotImplemented,
		"Kubernetes exec credential plugins are unsupported because their stderr cannot be governed",
		nil,
	).WithSuggestion("use a static bearer token or client certificate in the selected kubeconfig context")
}

func (c coordinate) coord() cfgov.Coordinate {
	return cfgov.Coordinate{Namespace: c.Namespace, Key: c.Kind + "/" + c.Name + "/" + c.DataKey}
}

func (b *Backend) tracef(format string, args ...any) {
	if !b.trace {
		return
	}
	_, _ = fmt.Fprintf(b.traceOut, format, args...)
}

func redactRef(c coordinate, valueBytes int) string {
	return fmt.Sprintf("%s/%s/%s/%s value=<redacted:%d>", c.Namespace, c.Kind, c.Name, c.DataKey, valueBytes)
}

func redactPrefix(prefix string) string {
	if prefix == "" {
		return ""
	}
	return fmt.Sprintf("<prefix:%d>", len(prefix))
}

func defaultKubeconfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
