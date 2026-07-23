package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestNewClientNormalizesPublicNamespaceToDefaultTenant(t *testing.T) {
	t.Parallel()
	client := NewClient("http://nacos.example", "", "", "public", time.Second)
	if got := client.Namespace(); got != "" {
		t.Fatalf("Namespace() = %q, want empty public tenant", got)
	}
}

func TestNewClientKeepsNonPublicNamespace(t *testing.T) {
	t.Parallel()
	client := NewClient("http://nacos.example", "", "", "wmc_dev", time.Second)
	if got := client.Namespace(); got != "wmc_dev" {
		t.Fatalf("Namespace() = %q, want wmc_dev", got)
	}
}

func TestWithNamespaceNormalizesPublicNamespaceToDefaultTenant(t *testing.T) {
	t.Parallel()
	client := NewClient("http://nacos.example", "", "", "wmc_dev", time.Second).WithNamespace("public")
	if got := client.Namespace(); got != "" {
		t.Fatalf("Namespace() = %q, want empty public tenant", got)
	}
}

func TestSlowAuthWarningUsesConfiguredDiagnosticWriter(t *testing.T) {
	t.Parallel()

	var diagnostic bytes.Buffer
	client := NewClient("http://nacos.example", "", "", "", time.Second)
	client.SetTrace(TraceOptions{Writer: &diagnostic})
	client.warnSlowAuth(1500 * time.Millisecond)

	if got := diagnostic.String(); !strings.Contains(got, "warning: nacos authentication took 1.5s") {
		t.Fatalf("slow authentication diagnostic = %q", got)
	}
}

func TestRetryDiagnosticRedactsSensitiveURLFromError(t *testing.T) {
	t.Parallel()

	const secret = "retry-token-secret"
	var diagnostic bytes.Buffer
	client := NewClient("http://nacos.example", "", "", "", time.Second)
	client.SetTrace(TraceOptions{Debug: true, Writer: &diagnostic})
	client.retryDebug(
		http.MethodGet,
		"/nacos/v1/cs/configs",
		0,
		errors.New(`Get "https://nacos.example/config?accessToken=`+secret+`": connection reset`),
	)

	got := diagnostic.String()
	if strings.Contains(got, secret) || !strings.Contains(got, "accessToken="+redactedMask) {
		t.Fatalf("retry diagnostic was not redacted: %q", got)
	}
}

func TestTraceOmitsRequestAndResponseBodies(t *testing.T) {
	t.Parallel()
	const (
		requestSecret        = "request-secret-value"
		requestCookieSecret  = "request-cookie-secret"
		requestHeaderSecret  = "request-header-secret"
		requestDebugSecret   = "request-debug-secret"
		responseSecret       = "response-secret-value"
		responseCookieSecret = "response-cookie-secret"
		responseDebugSecret  = "response-debug-secret"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Set-Cookie", "session="+responseCookieSecret)
		w.Header().Set("X-Debug", "token="+responseDebugSecret)
		_, _ = w.Write([]byte("password: " + responseSecret + "\n"))
	}))
	defer server.Close()

	var trace bytes.Buffer
	client := NewClient(server.URL, "", "", "", time.Second)
	client.SetTrace(TraceOptions{Trace: true, BodyLimit: 2048, Writer: &trace})
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL,
		strings.NewReader("password: "+requestSecret),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "session="+requestCookieSecret)
	req.Header.Set("X-Api-Key", requestHeaderSecret)
	req.Header.Set("X-Debug", "token="+requestDebugSecret)
	traced, err := client.doRequest(req)
	if err != nil {
		t.Fatalf("doRequest() error = %v", err)
	}
	if _, err := client.readResponse(traced); err != nil {
		t.Fatalf("readResponse() error = %v", err)
	}
	got := trace.String()
	for _, secret := range []string{
		requestSecret,
		requestCookieSecret,
		requestHeaderSecret,
		requestDebugSecret,
		responseSecret,
		responseCookieSecret,
		responseDebugSecret,
		"password:",
	} {
		if strings.Contains(got, secret) {
			t.Fatalf("trace leaked %q:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, "POST") || !strings.Contains(got, "200") {
		t.Fatalf("trace lost request metadata:\n%s", got)
	}
}

func TestResponseErrorsDoNotExposeBodies(t *testing.T) {
	t.Parallel()
	const secret = "server-error-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "password: "+secret, http.StatusInternalServerError)
	}))
	defer server.Close()

	var trace bytes.Buffer
	client := NewClient(server.URL, "", "", "", time.Second)
	client.SetTrace(TraceOptions{Trace: true, Writer: &trace})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	traced, err := client.doRequest(req)
	if err != nil {
		t.Fatalf("doRequest() error = %v", err)
	}
	_, err = client.readResponse(traced)
	if apperrors.AsAppError(err).Code != apperrors.CodeServerError {
		t.Fatalf("readResponse() error = %v, want server error", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(trace.String(), secret) {
		t.Fatalf("public error or trace leaked response body: err=%v trace=%s", err, trace.String())
	}
}

func TestListenErrorsDoNotExposeBodies(t *testing.T) {
	t.Parallel()
	const secret = "listener-error-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "token="+secret, http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "", "", time.Second)
	_, err := client.listenConfigOnce(
		context.Background(),
		"application.yaml",
		"DEFAULT_GROUP",
		"revision",
		10*time.Millisecond,
		false,
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeServerError {
		t.Fatalf("listenConfigOnce() error = %v, want server error", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("listener error leaked response body: %v", err)
	}
}

func TestBusinessErrorsKeepCodesWithoutExposingBodies(t *testing.T) {
	t.Parallel()
	const secret = "business-error-secret"
	err := unexpectedMutationResponse(
		"publish",
		[]byte(`{"code":409,"message":"already exists: `+secret+`"}`),
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeResourceAlreadyExists {
		t.Fatalf("unexpectedMutationResponse() error = %v, want already exists", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("business error leaked response body: %v", err)
	}

	err = unexpectedMutationResponse("publish", []byte("password: "+secret))
	if apperrors.AsAppError(err).Code != apperrors.CodeServerError {
		t.Fatalf("plain unexpected response error = %v, want server error", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("plain unexpected response leaked body: %v", err)
	}
}

func TestNacosInsecureSkipVerifyEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("NACOS_CLI_INSECURE_SKIP_VERIFY", "true")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "", "", "", time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.doRequest(req); err == nil {
		t.Fatal("doRequest() succeeded with an untrusted certificate because of a hidden environment override")
	}
}
