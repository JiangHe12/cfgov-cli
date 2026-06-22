// Package apollo adapts Apollo OpenAPI to cfgov.Backend.
//
// Coordinate mapping:
//   - Backend options carry Apollo appId, env, cluster, and a default namespace.
//   - cfgov.Coordinate.Namespace maps to the Apollo namespace. Empty means the
//     backend default namespace.
//   - cfgov.Coordinate.Key maps to the Apollo item key inside that namespace.
//
// Rule coordinate mapping:
//   - RuleCoordinate(app, type) maps to Coordinate{Namespace: ruleNamespace,
//     Key: "{app}-{type}-rules"}.
//   - ruleNamespace defaults to "SENTINEL" to match sentinel-cli Apollo wire
//     format and is intentionally separate from the config namespace default
//     "application".
package apollo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

const (
	defaultCluster       = "default"
	defaultNamespace     = "application"
	defaultRuleNamespace = "SENTINEL"
	defaultEnv           = "DEV"
)

type Options struct {
	Server        string
	Token         string
	AppID         string
	Env           string
	Cluster       string
	Namespace     string
	RuleNamespace string
	Operator      string
	Reason        string
	Timeout       time.Duration
	Trace         bool
	TraceOut      io.Writer
}

type Backend struct {
	server        string
	token         string
	appID         string
	env           string
	cluster       string
	namespace     string
	ruleNamespace string
	operator      string
	reason        string
	httpClient    *http.Client
	trace         bool
	traceOut      io.Writer
}

type itemResponse struct {
	Key                        string `json:"key"`
	Value                      string `json:"value"`
	DataChangeLastModifiedTime string `json:"dataChangeLastModifiedTime"`
	DataChangeCreatedTime      string `json:"dataChangeCreatedTime"`
}

type itemCreateRequest struct {
	Key                 string `json:"key"`
	Value               string `json:"value"`
	DataChangeCreatedBy string `json:"dataChangeCreatedBy"`
}

type itemUpdateRequest struct {
	Key                      string `json:"key"`
	Value                    string `json:"value"`
	DataChangeLastModifiedBy string `json:"dataChangeLastModifiedBy"`
}

type releaseRequest struct {
	ReleaseTitle   string `json:"releaseTitle"`
	ReleaseComment string `json:"releaseComment"`
	ReleasedBy     string `json:"releasedBy"`
}

type errorResponse struct {
	Status    int    `json:"status"`
	Message   string `json:"message"`
	Exception string `json:"exception"`
}

var (
	_ cfgov.Backend   = (*Backend)(nil)
	_ cfgov.RuleStore = (*Backend)(nil)
	_ cfgov.FlagStore = (*Backend)(nil)
)

func New(opts Options) (*Backend, error) {
	if err := validatePart("server", opts.Server, true); err != nil {
		return nil, err
	}
	if err := validatePart("appId", opts.AppID, false); err != nil {
		return nil, err
	}
	env := firstNonEmpty(opts.Env, defaultEnv)
	if err := validatePart("env", env, false); err != nil {
		return nil, err
	}
	cluster := firstNonEmpty(opts.Cluster, defaultCluster)
	if err := validatePart("cluster", cluster, false); err != nil {
		return nil, err
	}
	namespace := firstNonEmpty(opts.Namespace, defaultNamespace)
	if err := validatePart("namespace", namespace, false); err != nil {
		return nil, err
	}
	ruleNamespace := firstNonEmpty(opts.RuleNamespace, defaultRuleNamespace)
	if err := validatePart("rule namespace", ruleNamespace, false); err != nil {
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
	return &Backend{
		server:        strings.TrimRight(opts.Server, "/"),
		token:         opts.Token,
		appID:         opts.AppID,
		env:           env,
		cluster:       cluster,
		namespace:     namespace,
		ruleNamespace: ruleNamespace,
		operator:      firstNonEmpty(opts.Operator, "cfgov-cli"),
		reason:        opts.Reason,
		httpClient:    &http.Client{Timeout: timeout},
		trace:         opts.Trace,
		traceOut:      out,
	}, nil
}

func (b *Backend) Get(ctx context.Context, coord cfgov.Coordinate) (cfgov.Blob, error) {
	ns, key, err := b.resolve(coord)
	if err != nil {
		return cfgov.Blob{}, err
	}
	item, status, err := b.getItem(ctx, ns, key)
	if err != nil {
		return cfgov.Blob{}, err
	}
	if status == http.StatusNotFound {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeResourceNotFound, "apollo item not found", nil)
	}
	content := []byte(item.Value)
	return cfgov.Blob{Coordinate: cfgov.Coordinate{Namespace: ns, Key: key}, Content: content, Revision: itemRevision(item, content)}, nil
}

func (b *Backend) ValidateKey(key string) error {
	return validatePart("key", key, false)
}

func (b *Backend) Put(ctx context.Context, req cfgov.PutRequest) (cfgov.Blob, error) {
	ns, key, err := b.resolve(req.Coordinate)
	if err != nil {
		return cfgov.Blob{}, err
	}
	item, status, err := b.getItem(ctx, ns, key)
	if err != nil {
		return cfgov.Blob{}, err
	}
	exists := status != http.StatusNotFound
	if req.ExpectedRevision != "" && itemRevision(item, []byte(item.Value)) != req.ExpectedRevision {
		return cfgov.Blob{}, apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
	}
	if exists {
		err = b.updateItem(ctx, ns, key, req.Content)
	} else {
		err = b.createItem(ctx, ns, key, req.Content)
	}
	if err != nil {
		return cfgov.Blob{}, err
	}
	if err := b.release(ctx, ns, "put", key); err != nil {
		return cfgov.Blob{}, err
	}
	return b.Get(ctx, cfgov.Coordinate{Namespace: ns, Key: key})
}

func (b *Backend) Delete(ctx context.Context, req cfgov.DeleteRequest) error {
	ns, key, err := b.resolve(req.Coordinate)
	if err != nil {
		return err
	}
	if req.ExpectedRevision != "" {
		current, err := b.CurrentRevision(ctx, cfgov.Coordinate{Namespace: ns, Key: key})
		if err != nil {
			return err
		}
		if current != req.ExpectedRevision {
			return apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
		}
	}
	params := url.Values{}
	params.Set("operator", b.operator)
	body, status, err := b.do(ctx, http.MethodDelete, b.itemPath(ns, key), params, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if err := b.checkStatus(status, body, "apollo delete item failed"); err != nil {
		return err
	}
	return b.release(ctx, ns, "delete", key)
}

func (b *Backend) List(ctx context.Context, opts cfgov.ListOptions) ([]cfgov.ListItem, error) {
	ns := opts.Namespace
	if ns == "" {
		ns = b.namespace
	}
	if err := validatePart("namespace", ns, false); err != nil {
		return nil, err
	}
	if opts.Query != "" {
		if err := b.ValidateKey(opts.Query); err != nil {
			return nil, err
		}
	}
	body, status, err := b.do(ctx, http.MethodGet, b.itemsPath(ns), nil, nil)
	if err != nil {
		return nil, err
	}
	if err := b.checkStatus(status, body, "apollo list items failed"); err != nil {
		return nil, err
	}
	var items []itemResponse
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, apperrors.New(apperrors.CodeBackendError, "failed to decode apollo item list", err)
	}
	out := make([]cfgov.ListItem, 0, len(items))
	for _, item := range items {
		if opts.Query != "" && item.Key != opts.Query {
			continue
		}
		if opts.Prefix != "" && !strings.HasPrefix(item.Key, opts.Prefix) {
			continue
		}
		out = append(out, cfgov.ListItem{Coordinate: cfgov.Coordinate{Namespace: ns, Key: item.Key}, Revision: itemRevision(item, []byte(item.Value)), Type: "text"})
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Coordinate.Key < out[j].Coordinate.Key })
	return out, nil
}

func (b *Backend) History(context.Context, cfgov.Coordinate, cfgov.HistoryOptions) ([]cfgov.HistoryItem, int, error) {
	return nil, 0, apperrors.New(apperrors.CodeNotImplemented, "apollo backend does not support config history", nil)
}

func (b *Backend) Watch(context.Context, cfgov.Coordinate, string, cfgov.WatchOptions) (cfgov.WatchEvent, error) {
	return cfgov.WatchEvent{}, apperrors.New(apperrors.CodeNotImplemented, "apollo backend does not support config watch", nil)
}

func (b *Backend) CurrentRevision(ctx context.Context, coord cfgov.Coordinate) (string, error) {
	blob, err := b.Get(ctx, coord)
	if err != nil {
		return "", err
	}
	return blob.Revision, nil
}

func (b *Backend) Ping(ctx context.Context) error {
	body, status, err := b.do(ctx, http.MethodGet, fmt.Sprintf("/apps/%s/envclusters", escape(b.appID)), nil, nil)
	if err != nil {
		return err
	}
	if status >= 200 && status < 300 {
		return nil
	}
	return b.errorFromStatus(status, body, "apollo ping failed")
}

func (b *Backend) Describe() cfgov.Description {
	return cfgov.Description{Backend: "apollo", Server: b.server, Namespace: b.namespace}
}

func (b *Backend) Capabilities() cfgov.Capabilities {
	return cfgov.Capabilities{
		Backend:          "apollo",
		ResourceTypes:    []string{"config", "rule", "flag"},
		Verbs:            []string{"get", "list", "diff", "validate", "pull", "push", "delete"},
		SupportsCAS:      true,
		SupportsRevision: true,
		SupportsHistory:  false,
		SupportsWatch:    false,
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
	if err := validatePart("rule namespace", b.ruleNamespace, false); err != nil {
		return cfgov.Coordinate{}, err
	}
	if err := validatePart("rule key", dataID, false); err != nil {
		return cfgov.Coordinate{}, err
	}
	return cfgov.Coordinate{Namespace: b.ruleNamespace, Key: dataID}, nil
}

func (b *Backend) FlagCoordinate(app string) (cfgov.Coordinate, error) {
	dataID, err := flag.DataID(app)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	if err := validatePart("flag namespace", b.namespace, false); err != nil {
		return cfgov.Coordinate{}, err
	}
	if err := validatePart("flag key", dataID, false); err != nil {
		return cfgov.Coordinate{}, err
	}
	return cfgov.Coordinate{Namespace: b.namespace, Key: dataID}, nil
}

func (b *Backend) resolve(coord cfgov.Coordinate) (string, string, error) {
	ns := coord.Namespace
	if ns == "" {
		ns = b.namespace
	}
	if err := validatePart("namespace", ns, false); err != nil {
		return "", "", err
	}
	if err := validatePart("key", coord.Key, false); err != nil {
		return "", "", err
	}
	return ns, coord.Key, nil
}

func (b *Backend) getItem(ctx context.Context, namespace, key string) (itemResponse, int, error) {
	body, status, err := b.do(ctx, http.MethodGet, b.itemPath(namespace, key), nil, nil)
	if err != nil {
		return itemResponse{}, 0, err
	}
	if status == http.StatusNotFound {
		return itemResponse{}, status, nil
	}
	if err := b.checkStatus(status, body, "apollo get item failed"); err != nil {
		return itemResponse{}, status, err
	}
	var item itemResponse
	if err := json.Unmarshal(body, &item); err != nil {
		return itemResponse{}, status, apperrors.New(apperrors.CodeBackendError, "failed to decode apollo item response", err)
	}
	return item, status, nil
}

func (b *Backend) createItem(ctx context.Context, namespace, key string, content []byte) error {
	req := itemCreateRequest{Key: key, Value: string(content), DataChangeCreatedBy: b.operator}
	body, status, err := b.doJSON(ctx, http.MethodPost, b.itemsPath(namespace), nil, req)
	if err != nil {
		return err
	}
	return b.checkStatus(status, body, "apollo create item failed")
}

func (b *Backend) updateItem(ctx context.Context, namespace, key string, content []byte) error {
	req := itemUpdateRequest{Key: key, Value: string(content), DataChangeLastModifiedBy: b.operator}
	body, status, err := b.doJSON(ctx, http.MethodPut, b.itemPath(namespace, key), nil, req)
	if err != nil {
		return err
	}
	return b.checkStatus(status, body, "apollo update item failed")
}

func (b *Backend) release(ctx context.Context, namespace, action, key string) error {
	comment := b.reason
	if comment == "" {
		comment = fmt.Sprintf("%s: %s %s", b.operator, action, key)
	}
	req := releaseRequest{
		ReleaseTitle:   "cfgov-cli " + time.Now().UTC().Format(time.RFC3339),
		ReleaseComment: comment,
		ReleasedBy:     b.operator,
	}
	body, status, err := b.doJSON(ctx, http.MethodPost, b.releasePath(namespace), nil, req)
	if err != nil {
		return err
	}
	if err := b.checkStatus(status, body, "apollo release failed"); err != nil {
		return apperrors.New(apperrors.CodeBackendError, fmt.Sprintf("item updated but release failed: %s", err.Error()), err)
	}
	return nil
}

func (b *Backend) doJSON(ctx context.Context, method, path string, params url.Values, value any) ([]byte, int, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, 0, apperrors.New(apperrors.CodeBackendError, "failed to encode apollo request", err)
	}
	return b.do(ctx, method, path, params, data)
}

func (b *Backend) do(ctx context.Context, method, path string, params url.Values, body []byte) ([]byte, int, error) {
	req, err := b.newRequest(ctx, method, path, params, body)
	if err != nil {
		return nil, 0, err
	}
	if b.trace {
		b.tracef("[trace] >>> %s %s\n", method, redactURL(req.URL.String()))
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, 0, apperrors.New(apperrors.CodeBackendUnreachable, "apollo request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if b.trace {
		b.tracef("[trace] <<< %s\n", resp.Status)
	}
	if readErr != nil {
		return nil, resp.StatusCode, apperrors.New(apperrors.CodeBackendError, "failed to read apollo response", readErr)
	}
	return respBody, resp.StatusCode, nil
}

func (b *Backend) newRequest(ctx context.Context, method, path string, params url.Values, body []byte) (*http.Request, error) {
	reqURL := b.server + "/openapi/v1" + path
	if params != nil {
		if encoded := params.Encode(); encoded != "" {
			reqURL += "?" + encoded
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if b.token != "" {
		req.Header.Set("Authorization", b.token)
	}
	return req, nil
}

func (b *Backend) checkStatus(status int, body []byte, prefix string) error {
	if status >= 200 && status < 300 {
		return nil
	}
	return b.errorFromStatus(status, body, prefix)
}

func (b *Backend) errorFromStatus(status int, body []byte, prefix string) error {
	message := parseErrorBody(body)
	if message == "" {
		message = http.StatusText(status)
	}
	return apperrors.New(apperrors.CodeBackendError, fmt.Sprintf("%s: HTTP %d: %s", prefix, status, message), nil)
}

func (b *Backend) itemsPath(namespace string) string {
	return fmt.Sprintf("/envs/%s/apps/%s/clusters/%s/namespaces/%s/items",
		escape(b.env), escape(b.appID), escape(b.cluster), escape(namespace))
}

func (b *Backend) itemPath(namespace, key string) string {
	return b.itemsPath(namespace) + "/" + escape(key)
}

func (b *Backend) releasePath(namespace string) string {
	return fmt.Sprintf("/envs/%s/apps/%s/clusters/%s/namespaces/%s/releases",
		escape(b.env), escape(b.appID), escape(b.cluster), escape(namespace))
}

func (b *Backend) tracef(format string, args ...any) {
	_, _ = fmt.Fprintf(b.traceOut, format, args...)
}

func validatePart(name, value string, allowURL bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return apperrors.New(apperrors.CodeUsageError, name+" is required", nil)
	}
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return apperrors.New(apperrors.CodeValidationFailed, name+" contains invalid control characters", nil)
	}
	if allowURL {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return apperrors.New(apperrors.CodeUsageError, "invalid Apollo server URL", err)
		}
		return nil
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return apperrors.New(apperrors.CodeValidationFailed, name+" contains invalid path characters", nil)
	}
	return nil
}

func itemRevision(item itemResponse, content []byte) string {
	if item.DataChangeLastModifiedTime != "" {
		return item.DataChangeLastModifiedTime
	}
	if item.DataChangeCreatedTime != "" {
		return item.DataChangeCreatedTime
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func parseErrorBody(body []byte) string {
	var decoded errorResponse
	if err := json.Unmarshal(body, &decoded); err == nil {
		parts := make([]string, 0, 2)
		if decoded.Message != "" {
			parts = append(parts, decoded.Message)
		}
		if decoded.Exception != "" {
			parts = append(parts, decoded.Exception)
		}
		return strings.Join(parts, ": ")
	}
	return strings.TrimSpace(string(body))
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<redacted>"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "<redacted>")
	}
	q := u.Query()
	for key := range q {
		if strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "secret") {
			q.Set(key, "<redacted>")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func escape(value string) string {
	return url.PathEscape(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
