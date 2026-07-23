package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

func TestMandatoryReadSuccessPersistsPairedSanitizedRecords(t *testing.T) {
	const (
		requestSecret = "request-secret-value"
		resultSecret  = "result-secret-value"
	)
	var records []mutationAuditRecord
	f, auditPath := readAuditTestFlags(t)
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			records = append(records, record)
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, int64(len(records))).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x22}, 16)),
	}

	result, err := runMandatoryRead(
		f,
		readAuditSpecWithPath(
			newReadAuditSpec(
				"config.test",
				cfgovContextForReadAuditTest(),
				"config",
				requestSecret,
				map[string]string{"filter": requestSecret},
			),
			auditPath,
		),
		func() (string, error) {
			if len(records) != 1 || records[0].Phase != mutationAuditPhaseIntent {
				t.Fatalf("records at backend access = %+v, want one durable intent", records)
			}
			return resultSecret, nil
		},
		func(string) int { return 3 },
	)
	if err != nil {
		t.Fatalf("runMandatoryRead() error = %v", err)
	}
	if result != resultSecret {
		t.Fatalf("result = %q, want %q", result, resultSecret)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v, want intent and outcome", records)
	}
	if records[0].Kind != readAuditKind ||
		records[1].Kind != readAuditKind ||
		records[0].OperationID == "" ||
		records[0].OperationID != records[1].OperationID ||
		records[0].MutationID != "" ||
		records[1].MutationID != "" {
		t.Fatalf("read audit identities = %+v, want paired operationId-only records", records)
	}
	if records[1].Outcome == nil ||
		records[1].Outcome.Status != audit.StatusSuccess ||
		records[1].Outcome.Succeeded != 1 ||
		records[1].Outcome.ResultCount != 3 {
		t.Fatalf("outcome = %+v, want success with resultCount=3", records[1].Outcome)
	}
	data, marshalErr := json.Marshal(records)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	serialized := string(data)
	if strings.Contains(serialized, requestSecret) || strings.Contains(serialized, resultSecret) {
		t.Fatalf("read audit leaked request or result content: %s", serialized)
	}
}

func TestMandatoryReadIntentFailurePreventsBackendAccess(t *testing.T) {
	f, auditPath := readAuditTestFlags(t)
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected intent failure")
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x11}, 16)),
	}
	backendCalls := 0

	result, err := runMandatoryRead(
		f,
		readAuditSpecWithPath(
			newReadAuditSpec("config.test", cfgovContextForReadAuditTest(), "config", "safe", nil),
			auditPath,
		),
		func() (string, error) {
			backendCalls++
			return "must-not-run", nil
		},
		func(string) int { return 1 },
	)

	if backendCalls != 0 {
		t.Fatalf("backend calls = %d, want 0", backendCalls)
	}
	if result != "" {
		t.Fatalf("result = %q, want zero value", result)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
	}
}

func TestMandatoryReadAuthorizationIsFailClosedBeforeBackend(t *testing.T) {
	const (
		reader  = "reader@host"
		unknown = "unknown@host"
	)
	for _, test := range []struct {
		name          string
		operator      string
		context       cfgovctx.Context
		wantCode      apperrors.ErrorCode
		wantCalls     int
		wantSucceeded bool
	}{
		{
			name:      "unknown operator denied",
			operator:  unknown,
			context:   cfgovctx.Context{Base: corectx.Base{Roles: map[string]string{reader: safety.RoleReader}}},
			wantCode:  apperrors.CodeAuthorizationRequired,
			wantCalls: 0,
		},
		{
			name:     "remote role source denied",
			operator: reader,
			context: cfgovctx.Context{
				Base: corectx.Base{
					Roles:       map[string]string{reader: safety.RoleReader},
					RolesSource: "url",
					RolesURL:    "https://roles.example.invalid",
				},
			},
			wantCode:  apperrors.CodeAuthorizationRequired,
			wantCalls: 0,
		},
		{
			name:     "reader allowed in protected context",
			operator: reader,
			context: cfgovctx.Context{Base: corectx.Base{
				Protected: true,
				Roles:     map[string]string{reader: safety.RoleReader},
			}},
			wantCalls:     1,
			wantSucceeded: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var records []mutationAuditRecord
			f, auditPath := readAuditTestFlags(t)
			f.trustedOperator = ""
			f.resolveOperator = func() (string, error) { return test.operator, nil }
			f.mutationAudit = committedReadAuditRuntime(&records, 0x24)
			f.mutationAudit.appendOrdinary = func(string, any, audit.Options) error { return nil }
			backendCalls := 0

			result, err := runMandatoryRead(
				f,
				readAuditSpecWithPath(
					newReadAuditSpec("config.rbac-test", test.context, "config", "safe", nil),
					auditPath,
				),
				func() (string, error) {
					backendCalls++
					return "allowed", nil
				},
				func(string) int { return 1 },
			)

			if backendCalls != test.wantCalls {
				t.Fatalf("backend calls = %d, want %d", backendCalls, test.wantCalls)
			}
			if test.wantSucceeded {
				if err != nil || result != "allowed" {
					t.Fatalf("result/error = %q/%v, want allowed", result, err)
				}
			} else {
				if result != "" || apperrors.AsAppError(err).Code != test.wantCode {
					t.Fatalf("result/error = %q/%v, want zero/%s", result, err, test.wantCode)
				}
			}
			if len(records) != 2 || records[0].Phase != mutationAuditPhaseIntent ||
				records[1].Phase != mutationAuditPhaseOutcome {
				t.Fatalf("records = %+v, want completed pair", records)
			}
			if !test.wantSucceeded &&
				(records[1].Outcome == nil ||
					records[1].Outcome.Status != audit.StatusFailed ||
					records[1].Outcome.ErrorCode != string(apperrors.CodeAuthorizationRequired)) {
				t.Fatalf("authorization outcome = %+v, want failed AUTHORIZATION_REQUIRED", records[1].Outcome)
			}
		})
	}
}

func TestMandatoryReadAuthorizesEveryNamedContext(t *testing.T) {
	const (
		operator      = "reader@host"
		sourceContext = "source"
		targetContext = "target"
	)
	targetMeta := cfgovctx.Context{Base: corectx.Base{
		Roles: map[string]string{operator: safety.RoleReader},
	}}
	sourceMeta := cfgovctx.Context{Base: corectx.Base{
		Roles: map[string]string{"other@host": safety.RoleReader},
	}}
	var records []mutationAuditRecord
	var deniedContexts []string
	f, auditPath := readAuditTestFlags(t)
	f.trustedOperator = ""
	f.resolveOperator = func() (string, error) { return operator, nil }
	f.mutationAudit = committedReadAuditRuntime(&records, 0x26)
	f.mutationAudit.appendOrdinary = func(_ string, record any, _ audit.Options) error {
		event, ok := record.(audit.Event)
		if ok && event.EventType == audit.EventAuthorizationDenied {
			deniedContexts = append(deniedContexts, event.Context.Name)
		}
		return nil
	}
	spec := readAuditSpecWithPath(
		newReadAuditSpec("config.named-test", targetMeta, "config", "target", nil),
		auditPath,
	)
	spec.ContextName = targetContext
	spec.Authorize = []readAuditAuthorization{
		{ContextName: targetContext, Context: targetMeta},
		{ContextName: sourceContext, Context: sourceMeta},
	}
	backendCalls := 0

	_, err := runMandatoryRead(
		f,
		spec,
		func() (string, error) {
			backendCalls++
			return "unreachable", nil
		},
		func(string) int { return 1 },
	)

	if backendCalls != 0 {
		t.Fatalf("backend calls = %d, want 0", backendCalls)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, code = %s, want AUTHORIZATION_REQUIRED", err, got)
	}
	if len(deniedContexts) != 1 || deniedContexts[0] != sourceContext {
		t.Fatalf("denied contexts = %v, want [%s]", deniedContexts, sourceContext)
	}
	if len(records) != 2 ||
		records[0].Context.Name != targetContext ||
		records[1].Context.Name != targetContext {
		t.Fatalf("records = %+v, want pair bound to target context", records)
	}
}

func TestMandatoryReadAuthorizesEverySnapshotForSameContextName(t *testing.T) {
	const (
		operator    = "reader@host"
		contextName = "shared"
	)
	allowedSnapshot := cfgovctx.Context{Base: corectx.Base{
		Roles: map[string]string{operator: safety.RoleReader},
	}}
	deniedSnapshot := cfgovctx.Context{Base: corectx.Base{
		Roles: map[string]string{"other@host": safety.RoleReader},
	}}
	var records []mutationAuditRecord
	f, auditPath := readAuditTestFlags(t)
	f.trustedOperator = ""
	f.resolveOperator = func() (string, error) { return operator, nil }
	f.mutationAudit = committedReadAuditRuntime(&records, 0x27)
	f.mutationAudit.appendOrdinary = func(string, any, audit.Options) error { return nil }
	spec := readAuditSpecWithPath(
		newReadAuditSpec("config.same-name-snapshot", allowedSnapshot, "config", "target", nil),
		auditPath,
	)
	spec.ContextName = contextName
	spec.Authorize = []readAuditAuthorization{
		{ContextName: contextName, Context: allowedSnapshot},
		{ContextName: contextName, Context: deniedSnapshot},
	}
	backendCalls := 0

	_, err := runMandatoryRead(
		f,
		spec,
		func() (string, error) {
			backendCalls++
			return "unreachable", nil
		},
		func(string) int { return 1 },
	)

	if backendCalls != 0 {
		t.Fatalf("backend calls = %d, want 0", backendCalls)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, code = %s, want AUTHORIZATION_REQUIRED", err, got)
	}
	if len(records) != 2 ||
		records[0].Phase != mutationAuditPhaseIntent ||
		records[1].Phase != mutationAuditPhaseOutcome ||
		records[1].Outcome == nil ||
		records[1].Outcome.ErrorCode != string(apperrors.CodeAuthorizationRequired) {
		t.Fatalf("records = %+v, want failed authorization pair", records)
	}
}

func TestMandatoryBackendReadIntentFailurePreventsBackendBuild(t *testing.T) {
	f, auditPath := readAuditTestFlags(t)
	f.Context = ""
	f.Backend = "nacos"
	f.Server = "https://backend.example.invalid"
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected intent failure")
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x25}, 16)),
	}
	f.mutationAuditPath = auditPath
	buildCalls := 0
	f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
		buildCalls++
		return fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}, nil
	}

	_, err := runMandatoryBackendRead(
		f,
		"config.build-test",
		"config",
		"safe",
		nil,
		func(cfgov.Backend, cfgovctx.Context) (string, error) { return "unreachable", nil },
		func(string) int { return 1 },
	)

	if buildCalls != 0 {
		t.Fatalf("backend build calls = %d, want 0", buildCalls)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
	}
}

func TestMandatoryBackendReadAuthorizesSameNameAdditionalSnapshotBeforeBuild(t *testing.T) {
	home := t.TempDir()
	cfgovctx.SetConfigPath(filepath.Join(home, "missing-config.yaml"))
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })

	const operator = "reader@host"
	f, _ := readAuditTestFlags(t)
	f.Context = ""
	f.Backend = "nacos"
	f.Server = "https://backend.example.invalid"
	f.trustedOperator = operator
	var diagnostics bytes.Buffer
	f.diagnosticOut = &diagnostics
	var records []mutationAuditRecord
	f.mutationAudit = committedReadAuditRuntime(&records, 0x28)
	f.mutationAudit.appendOrdinary = func(string, any, audit.Options) error { return nil }
	buildCalls := 0
	readCalls := 0
	f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
		buildCalls++
		return fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}, nil
	}
	deniedSnapshot := cfgovctx.Context{Base: corectx.Base{
		Roles: map[string]string{"other@host": safety.RoleReader},
	}}

	result, err := runMandatoryBackendRead(
		f,
		"config.same-name-build",
		"config",
		"key",
		nil,
		func(cfgov.Backend, cfgovctx.Context) (string, error) {
			readCalls++
			return "unreachable", nil
		},
		func(string) int { return 1 },
		readAuditAuthorization{ContextName: "direct", Context: deniedSnapshot},
	)

	if buildCalls != 0 || readCalls != 0 {
		t.Fatalf("calls after denied snapshot = build:%d read:%d, want 0/0", buildCalls, readCalls)
	}
	if result.Value != "" || diagnostics.Len() != 0 {
		t.Fatalf("released result/diagnostics = %q/%q, want empty", result.Value, diagnostics.String())
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, code = %s, want AUTHORIZATION_REQUIRED", err, got)
	}
	if len(records) != 2 || records[1].Outcome == nil ||
		records[1].Outcome.ErrorCode != string(apperrors.CodeAuthorizationRequired) {
		t.Fatalf("records = %+v, want failed authorization pair", records)
	}
}

func TestMandatoryReadBackendFailurePersistsOutcomeAndPreservesError(t *testing.T) {
	operationErr := apperrors.New(apperrors.CodeBackendError, "injected backend failure", nil)
	var records []mutationAuditRecord
	f, auditPath := readAuditTestFlags(t)
	f.mutationAudit = committedReadAuditRuntime(&records, 0x33)

	result, err := runMandatoryRead(
		f,
		readAuditSpecWithPath(
			newReadAuditSpec("config.test", cfgovContextForReadAuditTest(), "config", "safe", nil),
			auditPath,
		),
		func() (string, error) {
			return "unreleased", operationErr
		},
		func(string) int { return 1 },
	)

	if result != "" {
		t.Fatalf("result = %q, want zero value", result)
	}
	if !errors.Is(err, operationErr) {
		t.Fatalf("error = %v, want original backend error", err)
	}
	if len(records) != 2 || records[1].Outcome == nil {
		t.Fatalf("records = %+v, want intent and failed outcome", records)
	}
	if records[1].Outcome.Status != audit.StatusFailed ||
		records[1].Outcome.Failed != 1 ||
		records[1].Outcome.ErrorCode != string(apperrors.CodeBackendError) {
		t.Fatalf("outcome = %+v, want one BACKEND_ERROR failure", records[1].Outcome)
	}
}

func TestMandatoryReadOutcomeFailureSuppressesResultAndPreservesOperationError(t *testing.T) {
	for _, test := range []struct {
		name         string
		operationErr error
	}{
		{name: "successful backend"},
		{name: "failed backend", operationErr: apperrors.New(apperrors.CodeBackendError, "backend failed", nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			appendCalls := 0
			f, auditPath := readAuditTestFlags(t)
			var diagnostics bytes.Buffer
			f.diagnosticOut = &diagnostics
			f.mutationAudit = &mutationAuditRuntime{
				appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
					appendCalls++
					if appendCalls == 2 {
						return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome failure")
					}
					return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
				},
				now:    func() time.Time { return time.Unix(1_700_000_000, int64(appendCalls)).UTC() },
				random: bytes.NewReader(bytes.Repeat([]byte{0x44}, 16)),
			}

			result, err := runMandatoryRead(
				f,
				readAuditSpecWithPath(
					newReadAuditSpec("config.test", cfgovContextForReadAuditTest(), "config", "safe", nil),
					auditPath,
				),
				func() (string, error) {
					_, _ = fmt.Fprint(diagnosticWriter(f), "must-not-be-released diagnostic")
					return "must-not-be-released", test.operationErr
				},
				func(string) int { return 1 },
			)

			if result != "" {
				t.Fatalf("result = %q, want zero value", result)
			}
			if diagnostics.Len() != 0 {
				t.Fatalf("diagnostics = %q, want empty", diagnostics.String())
			}
			if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
				t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
			}
			if test.operationErr != nil && !errors.Is(err, test.operationErr) {
				t.Fatalf("error = %v, want backend error in cause chain", err)
			}
		})
	}
}

func TestMandatoryReadReleasesDiagnosticsOnlyAfterDurableOutcome(t *testing.T) {
	var records []mutationAuditRecord
	f, auditPath := readAuditTestFlags(t)
	outcomeCommitted := false
	releasedBeforeOutcome := false
	var diagnostics bytes.Buffer
	f.diagnosticOut = callbackWriter(func(p []byte) (int, error) {
		if !outcomeCommitted {
			releasedBeforeOutcome = true
		}
		return diagnostics.Write(p)
	})
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			records = append(records, record)
			if record.Phase == mutationAuditPhaseOutcome {
				outcomeCommitted = true
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, int64(len(records))).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x45}, 16)),
	}

	result, err := runMandatoryRead(
		f,
		readAuditSpecWithPath(
			newReadAuditSpec("config.diagnostic-order", cfgovContextForReadAuditTest(), "config", "safe", nil),
			auditPath,
		),
		func() (string, error) {
			_, _ = fmt.Fprint(diagnosticWriter(f), "sanitized trace")
			if diagnostics.Len() != 0 {
				t.Fatalf("diagnostics released during backend read: %q", diagnostics.String())
			}
			return "result", nil
		},
		func(string) int { return 1 },
	)

	if err != nil || result != "result" {
		t.Fatalf("result/error = %q/%v, want result/nil", result, err)
	}
	if releasedBeforeOutcome || diagnostics.String() != "sanitized trace" {
		t.Fatalf("releasedBeforeOutcome=%v diagnostics=%q", releasedBeforeOutcome, diagnostics.String())
	}
}

func TestMandatoryReadDiagnosticsAreBoundedAndMarked(t *testing.T) {
	f, auditPath := readAuditTestFlags(t)
	var diagnostics bytes.Buffer
	f.diagnosticOut = &diagnostics
	f.mutationAudit = committedReadAuditRuntime(new([]mutationAuditRecord), 0x46)
	payload := bytes.Repeat([]byte("x"), maxReadDiagnosticBytes+128)

	_, err := runMandatoryRead(
		f,
		readAuditSpecWithPath(
			newReadAuditSpec("config.diagnostic-limit", cfgovContextForReadAuditTest(), "config", "safe", nil),
			auditPath,
		),
		func() (string, error) {
			_, _ = diagnosticWriter(f).Write(payload)
			return "result", nil
		},
		func(string) int { return 1 },
	)
	if err != nil {
		t.Fatalf("runMandatoryRead() error = %v", err)
	}
	if diagnostics.Len() != maxReadDiagnosticBytes+len(readDiagnosticTruncated) {
		t.Fatalf("diagnostic bytes = %d, want %d", diagnostics.Len(), maxReadDiagnosticBytes+len(readDiagnosticTruncated))
	}
	if !strings.HasSuffix(diagnostics.String(), readDiagnosticTruncated) {
		t.Fatalf("diagnostics missing deterministic truncation marker")
	}
}

func TestDelayedReadDiagnosticsAreConcurrentAndPromoteSafe(t *testing.T) {
	t.Parallel()

	buffer := newDelayedReadDiagnostics()
	payload := bytes.Repeat([]byte("x"), 1024)
	var writers sync.WaitGroup
	for range 32 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			_, _ = buffer.Write(payload)
		}()
	}
	writers.Wait()

	var released bytes.Buffer
	buffer.complete(&released, true)
	releasedBytes := released.Len()
	if releasedBytes != 32*len(payload) {
		t.Fatalf("released diagnostic bytes = %d, want %d", releasedBytes, 32*len(payload))
	}
	_, _ = buffer.Write([]byte("late diagnostic"))
	buffer.complete(&released, true)
	if got := released.String()[releasedBytes:]; got != "late diagnostic" {
		t.Fatalf("promoted diagnostic = %q, want late diagnostic", got)
	}

	suppressed := newDelayedReadDiagnostics()
	_, _ = suppressed.Write([]byte("buffered"))
	suppressed.complete(&released, false)
	beforeSuppressedWrite := released.Len()
	_, _ = suppressed.Write([]byte("must stay suppressed"))
	if released.Len() != beforeSuppressedWrite {
		t.Fatalf("suppressed diagnostics leaked: %q", released.String()[beforeSuppressedWrite:])
	}
}

func TestMandatoryBackendReadPromotesDiagnosticsForLaterMutation(t *testing.T) {
	f, auditPath := readAuditTestFlags(t)
	f.Context = ""
	f.Backend = "fake"
	f.Server = "https://backend.example.invalid"
	cfgovctx.SetConfigPath(filepath.Join(filepath.Dir(auditPath), "missing-config.yaml"))
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	f.mutationAudit = committedReadAuditRuntime(new([]mutationAuditRecord), 0x47)
	var released bytes.Buffer
	f.diagnosticOut = &released
	var retained io.Writer
	f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
		retained = diagnosticWriter(f)
		return fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}, nil
	}

	_, err := runMandatoryBackendRead(
		f,
		"config.preflight-diagnostics",
		"config",
		"app.yaml",
		map[string]string{"key": "app.yaml"},
		func(cfgov.Backend, cfgovctx.Context) (int, error) {
			_, _ = fmt.Fprint(diagnosticWriter(f), "preflight diagnostic\n")
			if released.Len() != 0 {
				t.Fatalf("diagnostics released before read outcome: %q", released.String())
			}
			return 1, nil
		},
		func(int) int { return 1 },
	)
	if err != nil {
		t.Fatalf("runMandatoryBackendRead() error = %v", err)
	}
	if released.String() != "preflight diagnostic\n" {
		t.Fatalf("released preflight diagnostics = %q", released.String())
	}
	_, _ = fmt.Fprint(retained, "mutation diagnostic\n")
	if released.String() != "preflight diagnostic\nmutation diagnostic\n" {
		t.Fatalf("retained backend diagnostics = %q", released.String())
	}
}

func TestDiagnosticErrorsAreRedactedBeforeWrite(t *testing.T) {
	t.Parallel()

	const secret = "diagnostic-secret"
	got := redactedDiagnosticError(errors.New("backend failed: token=" + secret))
	if strings.Contains(got, secret) {
		t.Fatalf("redacted diagnostic error leaked secret: %q", got)
	}
}

func TestMandatoryReadBatchUsesOnePairWithBoundedCounts(t *testing.T) {
	var records []mutationAuditRecord
	f, auditPath := readAuditTestFlags(t)
	f.mutationAudit = committedReadAuditRuntime(&records, 0x55)
	backendCalls := 0

	results, err := runMandatoryRead(
		f,
		readAuditSpecWithPath(
			newReadAuditSpec(
				"rule.list",
				cfgovContextForReadAuditTest(),
				"rule",
				"secret-app",
				map[string]any{"types": []string{"flow", "degrade", "system"}},
			),
			auditPath,
		),
		func() ([]string, error) {
			for range 3 {
				backendCalls++
			}
			return []string{"one", "two", "three"}, nil
		},
		func(results []string) int { return len(results) },
	)
	if err != nil {
		t.Fatalf("runMandatoryRead() error = %v", err)
	}
	if backendCalls != 3 || len(results) != 3 {
		t.Fatalf("backend calls/results = %d/%d, want 3/3", backendCalls, len(results))
	}
	if len(records) != 2 || records[1].Outcome == nil {
		t.Fatalf("records = %+v, want one pair", records)
	}
	if records[1].Outcome.ResultCount != 3 ||
		records[1].Outcome.Succeeded != 1 ||
		records[0].Metadata.Items != 1 {
		t.Fatalf("records = %+v, want one logical read and resultCount=3", records)
	}
	if got := boundedReadAuditCount(maxReadAuditCount + 1); got != maxReadAuditCount {
		t.Fatalf("boundedReadAuditCount() = %d, want %d", got, maxReadAuditCount)
	}
}

func TestReadOutcomeSpoolReplaysBeforeNextIntent(t *testing.T) {
	f, auditPath := readAuditTestFlags(t)
	failOutcome := true
	var records []mutationAuditRecord
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			if failOutcome && record.Phase == mutationAuditPhaseOutcome {
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome failure")
			}
			records = append(records, record)
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now: func() time.Time { return time.Now().UTC() },
		random: bytes.NewReader(append(
			bytes.Repeat([]byte{0x66}, 16),
			bytes.Repeat([]byte{0x77}, 16)...,
		)),
	}
	first, err := beginReadAudit(f, readAuditSpecWithPath(
		newReadAuditSpec("config.first", cfgovContextForReadAuditTest(), "config", "first", nil),
		auditPath,
	))
	if err != nil {
		t.Fatalf("beginReadAudit() error = %v", err)
	}
	firstID := first.mutation.id
	if err := finishReadAudit(first, 1, nil); apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
		t.Fatalf("finishReadAudit() error = %v, want LOCAL_IO_ERROR", err)
	}

	records = nil
	failOutcome = false
	second, err := beginReadAudit(f, readAuditSpecWithPath(
		newReadAuditSpec("config.second", cfgovContextForReadAuditTest(), "config", "second", nil),
		auditPath,
	))
	if err != nil {
		t.Fatalf("second beginReadAudit() error = %v", err)
	}
	if len(records) != 2 ||
		records[0].OperationID != firstID ||
		records[0].Phase != mutationAuditPhaseOutcome ||
		records[1].OperationID != second.mutation.id ||
		records[1].Phase != mutationAuditPhaseIntent {
		t.Fatalf("replay/order records = %+v", records)
	}
}

func TestConfigGetMandatoryReadAuditBlocksAndWithholds(t *testing.T) {
	for _, test := range []struct {
		name             string
		failAppendCall   int
		wantBackendCalls int32
		wantSpoolOutcome bool
	}{
		{name: "intent failure", failAppendCall: 1, wantBackendCalls: 0},
		{name: "outcome failure", failAppendCall: 2, wantBackendCalls: 1, wantSpoolOutcome: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const responseSecret = "remote-config-secret"
			var backendCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/nacos/v1/cs/configs" {
					http.NotFound(w, r)
					return
				}
				backendCalls.Add(1)
				_, _ = w.Write([]byte(responseSecret))
			}))
			defer server.Close()

			f, auditPath := readAuditTestFlags(t)
			var diagnostics bytes.Buffer
			f.diagnosticOut = &diagnostics
			f.Trace = true
			appendCalls := 0
			f.mutationAudit = &mutationAuditRuntime{
				appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
					appendCalls++
					if appendCalls == test.failAppendCall {
						return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected append failure")
					}
					return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
				},
				now:    func() time.Time { return time.Unix(1_700_000_000, int64(appendCalls)).UTC() },
				random: bytes.NewReader(bytes.Repeat([]byte{0x88}, 16)),
			}

			output, err := executeReadAuditCommand(
				t,
				f,
				"--backend", "nacos",
				"--server", server.URL,
				"--namespace", "ns",
				"-o", "json",
				"config", "get", "--key", "app.yaml",
			)

			if output != "" || diagnostics.Len() != 0 || strings.Contains(output, responseSecret) {
				t.Fatalf("stdout/stderr = %q/%q, want no released result", output, diagnostics.String())
			}
			if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
				t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
			}
			if got := backendCalls.Load(); got != test.wantBackendCalls {
				t.Fatalf("backend calls = %d, want %d", got, test.wantBackendCalls)
			}
			if test.wantSpoolOutcome {
				matches, globErr := filepath.Glob(filepath.Join(mutationAuditSpoolPath(auditPath), "*.json"))
				if globErr != nil || len(matches) != 1 {
					t.Fatalf("spooled outcomes = %v, error = %v; want one", matches, globErr)
				}
			}
		})
	}
}

func TestConfigPushPlanWithholdsOutputWhenReadOutcomeFails(t *testing.T) {
	var backendCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/nacos/v1/cs/configs" {
			http.NotFound(w, r)
			return
		}
		backendCalls.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	f, _ := readAuditTestFlags(t)
	f.Context = ""
	appendCalls := 0
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			appendCalls++
			if appendCalls == 2 {
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome failure")
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, int64(appendCalls)).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x89}, 16)),
	}

	output, err := executeReadAuditCommand(
		t,
		f,
		"--backend", "nacos",
		"--server", server.URL,
		"--namespace", "ns",
		"--plan",
		"-o", "json",
		"config", "push",
		"--key", "app.yaml",
		"--content", "enabled: true",
		"--type", "yaml",
	)

	if output != "" {
		t.Fatalf("output = %q, want no released plan", output)
	}
	if got := backendCalls.Load(); got != 1 {
		t.Fatalf("backend calls = %d, want 1", got)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
	}
}

func TestConfigPullOutcomeFailureDoesNotWriteFile(t *testing.T) {
	var backendCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/nacos/v1/cs/configs" {
			http.NotFound(w, r)
			return
		}
		backendCalls.Add(1)
		_, _ = w.Write([]byte("remote-config"))
	}))
	defer server.Close()

	f, _ := readAuditTestFlags(t)
	f.Context = ""
	f.Trace = true
	var diagnostics bytes.Buffer
	f.diagnosticOut = &diagnostics
	appendCalls := 0
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			appendCalls++
			if appendCalls == 2 {
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome failure")
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, int64(appendCalls)).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x8a}, 16)),
	}
	outputFile := filepath.Join(t.TempDir(), "pulled.yaml")

	output, err := executeReadAuditCommand(
		t,
		f,
		"--backend", "nacos",
		"--server", server.URL,
		"--namespace", "ns",
		"config", "pull",
		"--key", "app.yaml",
		"--file", outputFile,
	)

	if output != "" || diagnostics.Len() != 0 {
		t.Fatalf("stdout/stderr = %q/%q, want empty", output, diagnostics.String())
	}
	if got := backendCalls.Load(); got != 1 {
		t.Fatalf("backend calls = %d, want 1", got)
	}
	if _, statErr := os.Stat(outputFile); !os.IsNotExist(statErr) {
		t.Fatalf("output file exists after failed read outcome: %v", statErr)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
	}
}

func TestConfigPushOutcomeFailurePreventsRemoteMutation(t *testing.T) {
	var readCalls atomic.Int32
	var writeCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nacos/v1/cs/configs" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			readCalls.Add(1)
			http.NotFound(w, r)
		case http.MethodPost:
			writeCalls.Add(1)
			_, _ = w.Write([]byte("true"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f, _ := readAuditTestFlags(t)
	f.Context = ""
	f.Yes = true
	f.Trace = true
	var diagnostics bytes.Buffer
	f.diagnosticOut = &diagnostics
	appendCalls := 0
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			appendCalls++
			if appendCalls == 2 {
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome failure")
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, int64(appendCalls)).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x8b}, 16)),
	}

	output, err := executeReadAuditCommand(
		t,
		f,
		"--backend", "nacos",
		"--server", server.URL,
		"--namespace", "ns",
		"config", "push",
		"--key", "app.yaml",
		"--content", "enabled: true",
		"--type", "yaml",
		"--yes",
	)

	if output != "" || diagnostics.Len() != 0 {
		t.Fatalf("stdout/stderr = %q/%q, want empty", output, diagnostics.String())
	}
	if got := readCalls.Load(); got != 1 {
		t.Fatalf("read calls = %d, want 1", got)
	}
	if got := writeCalls.Load(); got != 0 {
		t.Fatalf("write calls = %d, want 0", got)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
	}
}

func TestConfigListenRejectsOversizedBufferBeforeBackendBuild(t *testing.T) {
	f, _ := readAuditTestFlags(t)
	f.Context = ""
	f.Backend = "nacos"
	f.Server = "https://backend.example.invalid"
	buildCalls := 0
	f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
		buildCalls++
		return fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}, nil
	}

	output, err := executeReadAuditCommand(
		t,
		f,
		"config", "listen",
		"--key", "app.yaml",
		"--max-events", intString(maxConfigListenEvents+1),
	)

	if output != "" {
		t.Fatalf("output = %q, want empty", output)
	}
	if buildCalls != 0 {
		t.Fatalf("backend build calls = %d, want 0", buildCalls)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeUsageError {
		t.Fatalf("error = %v, code = %s, want USAGE_ERROR", err, got)
	}
}

func TestCapabilitiesAdvertiseMandatoryReadAudit(t *testing.T) {
	capabilities := buildCapabilities(newDefaultFlags(), cfgov.Capabilities{})
	if capabilities.Supported.ReadAudit != "required-intent-outcome" {
		t.Fatalf("supported.readAudit = %q, want required-intent-outcome", capabilities.Supported.ReadAudit)
	}
	if !containsAuditString(capabilities.Domain.Kinds, readAuditKind) {
		t.Fatalf("kinds = %v, want %s", capabilities.Domain.Kinds, readAuditKind)
	}
	if capabilities.Domain.Limits.MaxListenEvents != maxConfigListenEvents {
		t.Fatalf("maxListenEvents = %d, want %d", capabilities.Domain.Limits.MaxListenEvents, maxConfigListenEvents)
	}
}

func TestCapabilitiesDoesNotBuildBackend(t *testing.T) {
	f := newDefaultFlags()
	f.Backend = "nacos"
	f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
		t.Fatal("capabilities must not build a backend client")
		return nil, nil
	}

	capabilities := currentBackendCapabilities(f)
	if capabilities.Backend != "nacos" {
		t.Fatalf("backend = %q, want nacos", capabilities.Backend)
	}
}

func TestMandatoryBackendReadUsesAuthorizedContextSnapshot(t *testing.T) {
	home := t.TempDir()
	prepareMutationAuditTestParent(t, home)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfgovctx.SetConfigPath(filepath.Join(home, "config.yaml"))
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })

	const (
		contextName = "snapshot"
		operator    = "reader@host"
		oldServer   = "https://old.example.invalid"
		newServer   = "https://new.example.invalid"
	)
	oldContext := cfgovctx.Context{
		Base:    corectx.Base{Server: oldServer, Roles: map[string]string{operator: safety.RoleReader}},
		Backend: "nacos",
	}
	if err := cfgovctx.Set(contextName, oldContext); err != nil {
		t.Fatal(err)
	}

	f := mutationAuditTestFlags()
	f.Context = contextName
	f.trustedOperator = operator
	f.mutationAuditPath = filepath.Join(home, "audit.jsonl")
	intentSeen := false
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			if record.Kind == readAuditKind && record.Phase == mutationAuditPhaseIntent && !intentSeen {
				intentSeen = true
				replacement := oldContext
				replacement.Server = newServer
				replacement.Roles = map[string]string{"other@host": safety.RoleReader}
				if err := cfgovctx.Set(contextName, replacement); err != nil {
					return audit.AppendResult{State: audit.AppendCommitNotCommitted}, err
				}
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x91}, 64)),
	}
	var builtServer, builtName string
	f.backendBuilder = func(_ *cliFlags, contextMeta cfgovctx.Context, name string) (cfgov.Backend, error) {
		builtServer = contextMeta.Server
		builtName = name
		if contextMeta.Server == newServer {
			t.Fatal("builder received context state changed after authorization")
		}
		return fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}, nil
	}

	result, err := runMandatoryBackendRead(
		f,
		"config.snapshot-test",
		"config",
		"key",
		map[string]string{"key": "key"},
		func(cfgov.Backend, cfgovctx.Context) (string, error) { return "ok", nil },
		func(string) int { return 1 },
	)
	if err != nil {
		t.Fatalf("runMandatoryBackendRead() error = %v", err)
	}
	if !intentSeen || result.Value != "ok" || builtServer != oldServer || builtName != contextName {
		t.Fatalf("intent=%v result=%q builtServer=%q builtName=%q", intentSeen, result.Value, builtServer, builtName)
	}
}

func TestAuthorizedBackendMutationStopsBeforeBuild(t *testing.T) {
	for _, test := range []struct {
		name       string
		context    cfgovctx.Context
		failIntent bool
		wantCode   apperrors.ErrorCode
	}{
		{
			name:     "elevated authorization denied",
			context:  cfgovctx.Context{Base: corectx.Base{Roles: map[string]string{"tester@host": safety.RoleReader}}},
			wantCode: apperrors.CodeAuthorizationRequired,
		},
		{
			name:       "mutation intent not durable",
			context:    cfgovctx.Context{Base: corectx.Base{Roles: map[string]string{"tester@host": safety.RoleAdmin}}},
			failIntent: true,
			wantCode:   apperrors.CodeLocalIOError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, auditPath := readAuditTestFlags(t)
			f.Context = "governed"
			f.Yes = true
			buildCalls := 0
			writeCalls := 0
			f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
				buildCalls++
				return fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}, nil
			}
			appendCalls := 0
			f.mutationAudit = &mutationAuditRuntime{
				appendRecord: func(_ string, _ mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
					appendCalls++
					if test.failIntent {
						return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected intent failure")
					}
					return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
				},
				now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
				random: bytes.NewReader(bytes.Repeat([]byte{0x92}, 64)),
			}
			_, err := runAuthorizedBackendMutation(
				f,
				test.context,
				"governed",
				safety.R1,
				"",
				mutationAuditSpec{
					Action:    "service.register",
					Target:    audit.EventTarget{ResourceType: "service", Resource: "svc"},
					AuditPath: auditPath,
				},
				func(cfgov.Backend, cfgovctx.Context) error {
					writeCalls++
					return nil
				},
			)
			if got := apperrors.AsAppError(err).Code; got != test.wantCode {
				t.Fatalf("error = %v, code = %s, want %s", err, got, test.wantCode)
			}
			if buildCalls != 0 || writeCalls != 0 {
				t.Fatalf("calls after fail-closed gate = build:%d write:%d, want 0/0", buildCalls, writeCalls)
			}
			if !test.failIntent && appendCalls != 0 {
				t.Fatalf("audit appends after authorization denial = %d, want 0", appendCalls)
			}
		})
	}
}

func TestSchemaWritePreflightIntentFailureDoesNotBuildBackend(t *testing.T) {
	home := t.TempDir()
	prepareMutationAuditTestParent(t, home)
	cfgovctx.SetConfigPath(filepath.Join(home, "missing-config.yaml"))
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })

	for _, test := range []struct {
		name string
		run  func(context.Context, *cliFlags) error
	}{
		{
			name: "flag",
			run: func(ctx context.Context, f *cliFlags) error {
				_, err := runFlagWritePreflight(
					ctx,
					f,
					flagWriteOptions{app: "app", action: "update"},
					safety.R1,
					map[string]any{},
					func(flagSetResult) ([]flag.FeatureFlag, error) { return nil, nil },
				)
				return err
			},
		},
		{
			name: "rule",
			run: func(ctx context.Context, f *cliFlags) error {
				_, err := runRuleWritePreflight(
					ctx,
					f,
					"app",
					"update",
					safety.R1,
					[]rule.Type{rule.TypeFlow},
					false,
					map[string]any{},
					func(rule.Type, ruleSetResult) ([]map[string]any, error) { return nil, nil },
				)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _ := readAuditTestFlags(t)
			f.Context = ""
			f.Backend = "nacos"
			f.Server = "https://backend.example.invalid"
			buildCalls := 0
			f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
				buildCalls++
				return fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}, nil
			}
			f.mutationAudit = &mutationAuditRuntime{
				appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
					return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected read intent failure")
				},
				now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
				random: bytes.NewReader(bytes.Repeat([]byte{0x93}, 64)),
			}
			err := test.run(t.Context(), f)
			if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
				t.Fatalf("error = %v, code = %s, want LOCAL_IO_ERROR", err, got)
			}
			if buildCalls != 0 {
				t.Fatalf("backend build calls = %d, want 0", buildCalls)
			}
		})
	}
}

func readAuditTestFlags(t *testing.T) (*cliFlags, string) {
	t.Helper()
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	f := mutationAuditTestFlags()
	path := filepath.Join(root, "audit.log")
	f.mutationAuditPath = path
	return f, path
}

func readAuditSpecWithPath(spec readAuditSpec, path string) readAuditSpec {
	spec.AuditPath = path
	return spec
}

func cfgovContextForReadAuditTest() cfgovctx.Context {
	return cfgovctx.Context{}
}

func committedReadAuditRuntime(records *[]mutationAuditRecord, randomByte byte) *mutationAuditRuntime {
	return &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			*records = append(*records, record)
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, int64(len(*records))).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{randomByte}, 16)),
	}
}

func executeReadAuditCommand(t *testing.T, f *cliFlags, args ...string) (string, error) {
	t.Helper()
	command := newRootCmdWith(f)
	command.SetArgs(args)
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	runErr := command.Execute()
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	os.Stdout = oldStdout
	var output strings.Builder
	if _, err := io.Copy(&output, reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return output.String(), runErr
}

type callbackWriter func([]byte) (int, error)

func (write callbackWriter) Write(p []byte) (int, error) {
	return write(p)
}
