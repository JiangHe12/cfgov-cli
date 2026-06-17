// internal/api/client.go
// 统一 HTTP Client，封装 Nacos Open API 认证与请求逻辑
// 所有 API 方法挂在 Client 上，方便扩展

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
)

const getMaxRetries = 3

// Client 是 Nacos API 的统一入口
type Client struct {
	baseURL    string
	username   string
	password   string
	namespace  string
	httpClient *http.Client
	// listenClient is a cached client used only by long-poll listen operations.
	// It reuses the transport from httpClient but omits the global Timeout so
	// long-poll requests are not aborted early.
	listenClient *http.Client
	// tokenMu guards accessToken read/write and serializes login attempts so
	// concurrent goroutines (e.g. batch GetConfig in import/reconcile) do
	// not race on a token refresh.
	tokenMu     sync.Mutex
	accessToken string
	// traceMu guards trace read/write so concurrent doRequest/readResponse
	// calls do not race with SetTrace.
	traceMu sync.RWMutex
	trace   TraceOptions
}

type tracedResponse struct {
	resp    *http.Response
	elapsed time.Duration
}

type TraceOptions struct {
	Debug     bool
	Trace     bool
	BodyLimit int
	Writer    io.Writer
}

// NewClient 创建一个 Client，namespace 可为空（使用 Nacos 默认）。
func NewClient(baseURL, username, password, namespace string, timeout ...time.Duration) *Client {
	clientTimeout := 30 * time.Second
	if len(timeout) > 0 && timeout[0] > 0 {
		clientTimeout = timeout[0]
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		defaultTransport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport := defaultTransport.Clone()
	transport.MaxIdleConnsPerHost = 16
	if strings.EqualFold(os.Getenv("NACOS_CLI_INSECURE_SKIP_VERIFY"), "true") || os.Getenv("NACOS_CLI_INSECURE_SKIP_VERIFY") == "1" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in for private Nacos deployments
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		username:   username,
		password:   password,
		namespace:  namespace,
		httpClient: &http.Client{Timeout: clientTimeout, Transport: transport},
		// Pre-create listenClient so long-poll operations don't race on lazy init.
		// It reuses the transport from httpClient but omits the global Timeout so
		// long-poll requests are not aborted early.
		listenClient: &http.Client{Transport: transport},
	}
}

func (c *Client) SetTrace(opts TraceOptions) {
	if opts.BodyLimit < 0 {
		opts.BodyLimit = 2048
	}
	c.traceMu.Lock()
	c.trace = opts
	c.traceMu.Unlock()
}

// login 获取 accessToken（Nacos 鉴权模式）.
// Callers MUST hold tokenMu OR ensure no concurrent token writers. The
// double-check on c.accessToken below makes the common "concurrent ensureToken"
// path cheap: if another goroutine logged in first, we skip the HTTP call.
func (c *Client) login(ctx context.Context) error {
	return c.loginWithSlowWarning(ctx, true)
}

func (c *Client) loginWithSlowWarning(ctx context.Context, warnSlow bool) error { //nolint:gocyclo // Login retry handling is kept inline to preserve auth-flow readability.
	if c.username == "" {
		return nil // 未开启鉴权，跳过
	}
	if c.accessToken != "" {
		return nil
	}
	start := time.Now()
	for attempt := 0; ; attempt++ {
		params := url.Values{}
		params.Set("username", c.username)
		params.Set("password", c.password)

		req, err := c.newRequest(ctx, http.MethodPost, "/nacos/v1/auth/login", params)
		if err != nil {
			return err
		}
		traced, err := c.doRequest(req, params.Encode())
		if err != nil {
			if attempt < getMaxRetries && isRetryableNetErr(err) {
				c.retryDebug(http.MethodPost, "/nacos/v1/auth/login", attempt, err)
				if sleepErr := sleepWithContext(ctx, retryBackoff(attempt)); sleepErr != nil {
					return apperrors.AsAppError(sleepErr)
				}
				continue
			}
			return apperrors.New(apperrors.CodeNetworkError, "authentication request failed", err)
		}
		body, err := c.readResponse(traced)
		if err != nil {
			appErr := apperrors.AsAppError(err)
			if attempt < getMaxRetries && appErr != nil && (appErr.HTTPStatus >= 500 || appErr.HTTPStatus == http.StatusTooManyRequests) {
				c.retryDebug(http.MethodPost, "/nacos/v1/auth/login", attempt, err)
				if sleepErr := sleepWithContext(ctx, retryBackoff(attempt)); sleepErr != nil {
					return apperrors.AsAppError(sleepErr)
				}
				continue
			}
			return err
		}

		var result struct {
			AccessToken string `json:"accessToken"`
			TokenTTL    int    `json:"tokenTtl"`
		}
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&result); err != nil {
			return apperrors.New(apperrors.CodeBackendError, "login decode", err)
		}
		if result.AccessToken == "" {
			return apperrors.New(apperrors.CodeAuthFailed, "authentication failed", nil)
		}
		c.accessToken = result.AccessToken
		elapsed := time.Since(start)
		c.authDebug("authentication token acquired in %s", elapsed.Round(time.Millisecond))
		if warnSlow {
			c.warnSlowAuth(elapsed)
		}
		return nil
	}
}

// currentToken returns the cached access token under lock so concurrent
// readers do not race a token refresh.
func (c *Client) currentToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.accessToken
}

// get 发起 GET 请求，自动附加 accessToken
func (c *Client) get(ctx context.Context, path string, params url.Values) ([]byte, error) {
	return c.do(ctx, http.MethodGet, path, params, true, false)
}

// post 发起 POST 请求
func (c *Client) post(ctx context.Context, path string, params url.Values) ([]byte, error) {
	return c.do(ctx, http.MethodPost, path, params, true, false)
}

func (c *Client) postIdempotent(ctx context.Context, path string, params url.Values) ([]byte, error) {
	return c.do(ctx, http.MethodPost, path, params, true, true)
}

func (c *Client) putIdempotent(ctx context.Context, path string, params url.Values) ([]byte, error) {
	return c.do(ctx, http.MethodPut, path, params, true, true)
}

func (c *Client) deleteIdempotent(ctx context.Context, path string, params url.Values) ([]byte, error) {
	return c.do(ctx, http.MethodDelete, path, params, true, true)
}

func (c *Client) do(ctx context.Context, method, path string, params url.Values, retryAuth, retryMutation bool) ([]byte, error) { //nolint:gocyclo // HTTP retry/auth/body handling is the central request state machine.
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	params = cloneValues(params)
	usedToken := c.currentToken()
	if usedToken != "" {
		params.Del("accessToken")
		params.Set("accessToken", usedToken)
	}

	retryable := method == http.MethodGet || retryMutation

	for attempt := 0; ; attempt++ {
		req, err := c.newRequest(ctx, method, path, params)
		if err != nil {
			return nil, err
		}
		traced, err := c.doRequest(req, requestBodyFor(method, params))
		if err != nil {
			// Network error (DNS, timeout, connection refused, etc.)
			if retryable && attempt < getMaxRetries && isRetryableNetErr(err) {
				c.retryDebug(method, path, attempt, err)
				if err := sleepWithContext(ctx, retryBackoff(attempt)); err != nil {
					return nil, apperrors.AsAppError(err)
				}
				continue
			}
			return nil, apperrors.New(apperrors.CodeNetworkError, "network error", err)
		}
		resp := traced.resp
		if resp.StatusCode == http.StatusForbidden && retryAuth && c.username != "" {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			var retryBody []byte
			retried, err := c.handleAuthRetry(ctx, usedToken, fmt.Sprintf("%s %s", method, redactURL(path)), func() error {
				var retryErr error
				retryBody, retryErr = c.do(ctx, method, path, params, false, retryMutation)
				return retryErr
			})
			if retried || err != nil {
				return retryBody, err
			}
		}
		if resp.StatusCode == http.StatusForbidden && !retryAuth && c.username != "" {
			c.authDebug("HTTP 403 persisted for %s %s after token refresh; treating as authorization failure", method, redactURL(path))
		}
		// Retry on 5xx server errors and 429 (rate limit) for GET requests
		// and caller-declared idempotent mutations.
		if retryable && (resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests) && attempt < getMaxRetries {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			c.retryDebug(method, path, attempt, fmt.Errorf("HTTP %d", resp.StatusCode))
			if err := sleepWithContext(ctx, retryBackoff(attempt)); err != nil {
				return nil, apperrors.AsAppError(err)
			}
			continue
		}
		return c.readResponse(traced)
	}
}

// retryBackoff returns exponential backoff with jitter: base * 2^attempt + jitter.
func retryBackoff(attempt int) time.Duration {
	base := 200 * time.Millisecond
	delay := base * time.Duration(1<<uint(attempt))
	quarter := int64(delay) / 4
	if quarter <= 0 {
		quarter = 1
	}
	jitter := time.Duration(rand.Int63n(quarter)) //nolint:gosec // Retry jitter is not used for security decisions.
	return delay + jitter
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isRetryableNetErr returns true for network errors that are safe to retry
// (timeouts, connection refused, DNS errors).
func isRetryableNetErr(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		switch sysErr { //nolint:exhaustive // Only selected retryable errno values matter; all others are non-retryable.
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ETIMEDOUT, syscall.EPIPE:
			return true
		default:
			return false
		}
	}
	errStr := err.Error()
	// DNS errors, connection refused, connection reset — all transient.
	lower := strings.ToLower(errStr)
	return strings.Contains(lower, "dial") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "connection reset") ||
		strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "broken pipe")
}

// retryDebug logs retry attempts to stderr when debug is enabled.
func (c *Client) retryDebug(method, path string, attempt int, err error) {
	c.traceMu.RLock()
	t := c.trace
	c.traceMu.RUnlock()
	if t.Debug || t.Trace {
		c.tracef("[debug] retry %d/%d for %s %s due to: %s\n", attempt+1, getMaxRetries, method, redactURL(path), err)
	}
}

func (c *Client) authDebug(format string, args ...any) {
	c.traceMu.RLock()
	t := c.trace
	c.traceMu.RUnlock()
	if t.Debug || t.Trace {
		c.tracef("[debug] "+format+"\n", args...)
	}
}

func (c *Client) newRequest(ctx context.Context, method, path string, params url.Values) (*http.Request, error) {
	switch method {
	case http.MethodGet, http.MethodDelete:
		reqURL := fmt.Sprintf("%s%s?%s", c.baseURL, path, params.Encode())
		return http.NewRequestWithContext(ctx, method, reqURL, nil)
	case http.MethodPost, http.MethodPut:
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, strings.NewReader(params.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	default:
		return nil, apperrors.New(apperrors.CodeNotImplemented, fmt.Sprintf("unsupported method %s", method), nil)
	}
}

// relogin invalidates the cached token (if unchanged since the request that
// triggered the 403) and performs a fresh login. The lock serializes concurrent
// refreshes so only one goroutine actually hits the login endpoint; login()
// short-circuits if accessToken is already set by a peer goroutine.
func (c *Client) relogin(ctx context.Context, usedToken string) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != usedToken {
		return nil
	}
	c.accessToken = ""
	start := time.Now()
	err := c.loginWithSlowWarning(ctx, false)
	if err == nil {
		c.warnSlowAuth(time.Since(start))
	}
	return err
}

func (c *Client) handleAuthRetry(ctx context.Context, usedToken string, operation string, retryFn func() error) (bool, error) {
	if c.username == "" {
		return false, nil
	}
	c.authDebug("HTTP 403 received for %s; refreshing authentication token", operation)
	if err := c.relogin(ctx, usedToken); err != nil {
		return true, err
	}
	return true, retryFn()
}

func (c *Client) warnSlowAuth(elapsed time.Duration) {
	if elapsed > time.Second {
		_, _ = fmt.Fprintf(os.Stderr, "warning: nacos authentication took %s (consider checking nacos auth latency)\n", elapsed.Round(time.Millisecond))
	}
}

func (c *Client) ensureToken(ctx context.Context) error {
	if c.username == "" {
		return nil
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != "" {
		return nil
	}
	return c.login(ctx)
}

func (c *Client) doRequest(req *http.Request, body string) (*tracedResponse, error) {
	c.traceMu.RLock()
	t := c.trace
	c.traceMu.RUnlock()
	start := time.Now()
	if t.Trace {
		c.tracef("[trace] >>> %s %s\n", req.Method, redactURL(req.URL.String()))
		for _, key := range sortedHeaderKeys(req.Header) {
			values := req.Header.Values(key)
			for _, value := range values {
				c.tracef("[trace]     %s: %s\n", key, redactIfSensitive(key, value))
			}
		}
		if body != "" {
			c.tracef("[trace]     Body: %s\n", truncateTrace(redactFormBody(body), c.traceLimit()))
		}
	}
	resp, err := c.httpClient.Do(req) //nolint:bodyclose // reason: body is closed in readResponse via tracedResponse
	elapsed := time.Since(start)
	if err != nil {
		if t.Debug || t.Trace {
			c.tracef("[debug] %s %s error %s\n", req.Method, redactURL(req.URL.String()), elapsed.Round(time.Millisecond))
		}
		return nil, err
	}
	if t.Debug || t.Trace {
		c.tracef("[debug] %s %s %d %s\n", req.Method, redactURL(req.URL.String()), resp.StatusCode, elapsed.Round(time.Millisecond))
	}
	return &tracedResponse{resp: resp, elapsed: elapsed}, nil
}

const maxBodySize = 10 * 1024 * 1024 // 10 MB

func (c *Client) readResponse(traced *tracedResponse) ([]byte, error) {
	resp := traced.resp
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodySize {
		return nil, apperrors.New(apperrors.CodeServerError,
			fmt.Sprintf("response body exceeds %d MB limit", maxBodySize/(1024*1024)), nil)
	}
	c.traceMu.RLock()
	t := c.trace
	c.traceMu.RUnlock()
	if t.Trace {
		c.tracef("[trace] <<< %s (%s)\n", resp.Status, traced.elapsed.Round(time.Millisecond))
		for _, key := range sortedHeaderKeys(resp.Header) {
			values := resp.Header.Values(key)
			for _, value := range values {
				c.tracef("[trace]     %s: %s\n", key, redactIfSensitive(key, value))
			}
		}
		if len(body) > 0 {
			c.tracef("[trace]     Body: %s\n", truncateTrace(redactFormBody(string(body)), c.traceLimit()))
		}
	}
	if resp.StatusCode >= 400 {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, apperrors.FromHTTP(resp.StatusCode, message)
	}
	return body, nil
}

func (c *Client) traceLimit() int {
	c.traceMu.RLock()
	bl := c.trace.BodyLimit
	c.traceMu.RUnlock()
	if bl == 0 {
		return 0
	}
	if bl < 0 {
		return 2048
	}
	return bl
}

func (c *Client) tracef(format string, args ...any) {
	c.traceMu.RLock()
	w := c.trace.Writer
	c.traceMu.RUnlock()
	if w == nil {
		w = os.Stderr
	}
	_, _ = fmt.Fprintf(w, format, args...)
}

func requestBodyFor(method string, params url.Values) string {
	if method == http.MethodPost || method == http.MethodPut {
		return params.Encode()
	}
	return ""
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactFormBody(raw)
	}
	u.RawQuery = redactValues(u.Query()).Encode()
	return u.String()
}

func redactFormBody(body string) string {
	if !strings.Contains(body, "=") {
		return redactFreeText(body)
	}
	values, err := url.ParseQuery(body)
	if err != nil {
		return redactFreeText(body)
	}
	redacted := redactValues(values)
	parts := make([]string, 0, len(redacted))
	keys := make([]string, 0, len(redacted))
	for key := range redacted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range redacted[key] {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, "&")
}

func redactValues(values url.Values) url.Values {
	redacted := url.Values{}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range values[key] {
			redacted.Add(key, redactIfSensitive(key, value))
		}
	}
	return redacted
}

// redactedMask is the literal placeholder per GLOBAL_GUIDE.md §8.3 — credentials in
// debug/trace/audit/ChangePlan output are replaced with this exact string so the
// surrounding diagnostic structure stays parseable while no portion of the secret leaks.
const redactedMask = "<redacted>"

func redactIfSensitive(key, value string) string {
	if !isSensitiveKey(key) {
		return value
	}
	return redactedMask
}

func redactFreeText(s string) string {
	// Replace `<key>=<value>` only at word boundaries to avoid mangling
	// substrings (e.g. "mypassword=" should not match "password=").
	s = sensitiveFormPattern.ReplaceAllStringFunc(s, func(match string) string {
		idx := strings.LastIndex(match, "=")
		if idx < 0 {
			return match
		}
		return match[:idx+1] + redactedMask
	})
	s = sensitiveJSONPattern.ReplaceAllStringFunc(s, func(match string) string {
		idx := strings.Index(match, ":")
		if idx < 0 {
			return match
		}
		return match[:idx+1] + `"` + redactedMask + `"`
	})
	return s
}

var sensitiveJSONPattern = func() *regexp.Regexp {
	keys := strings.Join(sensitiveKeys, "|")
	return regexp.MustCompile(`"(?i:` + keys + `)"\s*:\s*"[^"]*"`)
}()

// sensitiveFormPattern matches `<key>=<value>` only when the key is
// preceded by a word boundary, so "mypassword=" stays intact.
var sensitiveFormPattern = func() *regexp.Regexp {
	keys := strings.Join(sensitiveKeys, "|")
	return regexp.MustCompile(`(?i)(^|[^a-zA-Z0-9_])(` + keys + `)=[^&\s]*`)
}()

var sensitiveKeys = []string{"password", "accessToken", "authorization", "secretKey", "token"}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(lower, strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}

func sortedHeaderKeys(header http.Header) []string {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func truncateTrace(s string, limit int) string {
	if limit == 0 || len(s) <= limit {
		return s
	}
	totalKB := (len(s) + 1023) / 1024
	return s[:limit] + fmt.Sprintf("...[truncated, total %dkb]", totalKB)
}

func unexpectedMutationResponse(action string, body []byte) error {
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = "<empty>"
	}
	// Nacos 2.x sometimes returns HTTP 200 with a JSON envelope describing a
	// business-layer failure: {"code":400,"message":"..."} or {"code":409,...}.
	// Project this onto the canonical error code so CI does not treat
	// "namespace already exists" as a retryable SERVER_ERROR.
	if nacosErr := parseNacosBusinessError(action, message); nacosErr != nil {
		return nacosErr
	}
	return apperrors.New(apperrors.CodeServerError, fmt.Sprintf("%s failed, server returned: %s", action, message), nil)
}

// parseNacosBusinessError detects the Nacos 2.x business envelope
// `{"code":N,"message":"..."}` returned alongside HTTP 200 on certain
// failures. Returns nil when the body does not match the envelope.
//
// It also handles two additional failure shapes:
//   - {"success":false,"code":0,"message":"..."} — success explicitly false
//     even though code is 0; the message is treated as a business error.
//   - {"success":false,"errorCode":"...","errorMessage":"..."} — Nacos 2.x
//     variant where errorCode is a string.
func parseNacosBusinessError(action, body string) error { //nolint:gocyclo // Handles several Nacos business-error envelope variants in one parser.
	if !strings.HasPrefix(body, "{") {
		return nil
	}
	var envelope struct {
		Code         int    `json:"code"`
		Message      string `json:"message"`
		Data         any    `json:"data"`
		Success      *bool  `json:"success"`
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	}
	if !json.Valid([]byte(body)) {
		return nil
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return apperrors.New(apperrors.CodeServerError, fmt.Sprintf("%s failed, server returned malformed JSON business error: %s", action, body), err)
	}

	// Nacos 2.x variant: {"success":false,"errorCode":"...","errorMessage":"..."}
	// errorCode is a string, not an integer code.
	if envelope.Success != nil && !*envelope.Success && envelope.ErrorCode != "" {
		msg := envelope.ErrorMessage
		if msg == "" {
			msg = fmt.Sprintf("nacos business error: %s", envelope.ErrorCode)
		}
		full := fmt.Sprintf("%s: %s", action, msg)
		return apperrors.New(nacosErrorCodeToAppCode(envelope.ErrorCode), full, nil)
	}

	// success explicitly false with code == 0 and a message — treat as error.
	if envelope.Success != nil && !*envelope.Success && envelope.Code == 0 {
		msg := envelope.Message
		if msg == "" {
			msg = "nacos business error: success=false"
		}
		full := fmt.Sprintf("%s: %s", action, msg)
		return apperrors.New(apperrors.CodeServerError, full, nil)
	}

	if envelope.Code == 0 || (envelope.Code >= 200 && envelope.Code < 300) {
		return nil
	}
	msg := envelope.Message
	if msg == "" {
		msg = fmt.Sprintf("nacos business error code=%d", envelope.Code)
	}
	full := fmt.Sprintf("%s: %s", action, msg)
	switch {
	case envelope.Code == 400 || envelope.Code == 422:
		return apperrors.New(apperrors.CodeValidationFailed, full, nil)
	case envelope.Code == 401:
		return apperrors.New(apperrors.CodeAuthFailed, full, nil)
	case envelope.Code == 403:
		return apperrors.New(apperrors.CodeAuthorizationRequired, full, nil)
	case envelope.Code == 404:
		return apperrors.New(apperrors.CodeResourceNotFound, full, nil)
	case envelope.Code == 409:
		// Nacos uses 409 for "already exists" (e.g. namespace duplication).
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "exist") {
			return apperrors.New(apperrors.CodeResourceAlreadyExists, full, nil)
		}
		return apperrors.New(apperrors.CodeConflict, full, nil)
	case envelope.Code >= 500:
		return apperrors.New(apperrors.CodeServerError, full, nil)
	default:
		return apperrors.New(apperrors.CodeServerError, full, nil)
	}
}

func nacosErrorCodeToAppCode(code string) apperrors.Code {
	switch strings.TrimSpace(code) {
	case "400", "422":
		return apperrors.CodeValidationFailed
	case "401":
		return apperrors.CodeAuthFailed
	case "403":
		return apperrors.CodeAuthorizationRequired
	case "404":
		return apperrors.CodeResourceNotFound
	case "409":
		return apperrors.CodeResourceAlreadyExists
	case "500", "502", "503", "504":
		return apperrors.CodeServerError
	default:
		return apperrors.CodeServerError
	}
}

// Namespace 返回 Client 的 namespace，供 cmd 层读取
func (c *Client) Namespace() string {
	return c.namespace
}

func (c *Client) WithNamespace(namespace string) *Client {
	next := NewClient(c.baseURL, c.username, c.password, namespace, c.httpClient.Timeout)
	c.traceMu.RLock()
	trace := c.trace
	c.traceMu.RUnlock()
	next.SetTrace(trace)
	return next
}

func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/nacos/v1/console/server/state", nil)
	if err != nil {
		return err
	}
	traced, err := c.doRequest(req, "")
	if err != nil {
		return apperrors.New(apperrors.CodeNetworkError, "network error", err)
	}
	_, err = c.readResponse(traced)
	return err
}

func (c *Client) CheckAuth(ctx context.Context) error {
	return c.ensureToken(ctx)
}

func cloneValues(values url.Values) url.Values {
	cloned := url.Values{}
	for key, list := range values {
		for _, value := range list {
			cloned.Add(key, value)
		}
	}
	return cloned
}
