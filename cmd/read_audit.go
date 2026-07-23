package cmd

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

const (
	maxReadAuditCount       = 1_000_000_000
	maxReadDiagnosticBytes  = 1 << 20
	readDiagnosticTruncated = "\nwarning: read diagnostics truncated at 1048576 bytes\n"
)

type readAuditSpec struct {
	Action      string
	ContextName string
	Context     cfgovctx.Context
	Authorize   []readAuditAuthorization
	Target      audit.EventTarget
	Metadata    mutationAuditMetadata
	AuditPath   string
}

type readAuditAuthorization struct {
	ContextName string
	Context     cfgovctx.Context
}

type readAuditHandle struct {
	mutation *mutationAuditHandle
}

type delayedReadDiagnostics struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
	done      bool
}

func newDelayedReadDiagnostics() *delayedReadDiagnostics {
	return &delayedReadDiagnostics{data: make([]byte, 0, maxReadDiagnosticBytes)}
}

func (buffer *delayedReadDiagnostics) Write(p []byte) (int, error) {
	written := len(p)
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if buffer.done {
		return written, nil
	}
	remaining := maxReadDiagnosticBytes - len(buffer.data)
	if remaining <= 0 {
		buffer.truncated = buffer.truncated || len(p) > 0
		return written, nil
	}
	if len(p) > remaining {
		buffer.data = append(buffer.data, p[:remaining]...)
		buffer.truncated = true
		return written, nil
	}
	buffer.data = append(buffer.data, p...)
	return written, nil
}

func (buffer *delayedReadDiagnostics) complete(out io.Writer, release bool) {
	buffer.mu.Lock()
	if buffer.done {
		buffer.mu.Unlock()
		return
	}
	buffer.done = true
	data := buffer.data
	truncated := buffer.truncated
	buffer.data = nil
	buffer.mu.Unlock()
	if !release {
		return
	}
	if len(data) > 0 {
		_, _ = out.Write(data)
	}
	if truncated {
		_, _ = fmt.Fprint(out, readDiagnosticTruncated)
	}
}

type mandatoryBackendReadResult[T any] struct {
	Backend     cfgov.Backend
	Context     cfgovctx.Context
	ContextName string
	Value       T
}

func (result mandatoryBackendReadResult[T]) operationTarget() operationTarget {
	return operationTargetFromDescription(result.ContextName, result.Backend.Describe())
}

func newReadAuditSpec(
	action string,
	contextMeta cfgovctx.Context,
	resourceType string,
	target string,
	request any,
) readAuditSpec {
	if target == "" {
		target = "*"
	}
	metadata := mutationValueMetadata("read-request:"+action, request)
	metadata.PayloadBytes = boundedReadAuditCount(metadata.PayloadBytes)
	metadata.Items = 1
	return readAuditSpec{
		Action:  action,
		Context: contextMeta,
		Target: audit.EventTarget{
			ResourceType: resourceType,
			Resource:     mutationAuditFingerprint("read-target:"+action, []byte(target)),
		},
		Metadata: metadata,
	}
}

func beginReadAudit(f *cliFlags, spec readAuditSpec) (*readAuditHandle, error) {
	metadata := spec.Metadata
	metadata.Items = boundedReadAuditCount(metadata.Items)
	if metadata.Items == 0 {
		metadata.Items = 1
	}
	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:      spec.Action,
		ContextName: spec.ContextName,
		Context:     spec.Context,
		Target:      spec.Target,
		Metadata:    metadata,
		AuditPath:   spec.AuditPath,
		Read:        true,
	})
	if err != nil {
		return nil, mandatoryReadAuditError("failed to persist mandatory read intent", err, nil)
	}
	return &readAuditHandle{mutation: handle}, nil
}

func finishReadAudit(handle *readAuditHandle, resultCount int, operationErr error) error {
	outcome := completedReadAuditOutcome(resultCount, operationErr)
	if err := persistReadAuditOutcome(handle, outcome, operationErr); err != nil {
		return err
	}
	return operationErr
}

func completedReadAuditOutcome(resultCount int, operationErr error) mutationAuditOutcome {
	outcome := mutationAuditOutcome{
		ResultCount: boundedReadAuditCount(resultCount),
	}
	if operationErr == nil {
		outcome.Succeeded = 1
	} else {
		outcome.Failed = 1
	}
	return outcome
}

func persistReadAuditOutcome(
	handle *readAuditHandle,
	outcome mutationAuditOutcome,
	operationErr error,
) error {
	if handle == nil || handle.mutation == nil {
		return apperrors.New(apperrors.CodeValidationFailed, "read audit handle is required", nil)
	}
	finishErr := finishMutationAudit(handle.mutation, outcome, operationErr)
	if finishErr == nil {
		return nil
	}
	if operationErr != nil && errors.Is(finishErr, operationErr) {
		return nil
	}
	return mandatoryReadAuditError("failed to persist mandatory read outcome", finishErr, operationErr)
}

func mandatoryReadAuditError(message string, auditErr, operationErr error) error {
	cause := auditErr
	if operationErr != nil {
		cause = errors.Join(auditErr, operationErr)
	}
	return apperrors.New(apperrors.CodeLocalIOError, message, cause).
		WithSuggestion("repair the audit path and retry; no read result was released")
}

func boundedReadAuditCount(value int) int {
	if value < 0 {
		return 0
	}
	if value > maxReadAuditCount {
		return maxReadAuditCount
	}
	return value
}

func runMandatoryRead[T any](
	f *cliFlags,
	spec readAuditSpec,
	operation func() (T, error),
	resultCount func(T) int,
) (T, error) {
	var zero T
	result, operationErr, auditErr := executeMandatoryRead(f, spec, operation, resultCount)
	if auditErr != nil {
		return zero, auditErr
	}
	if operationErr != nil {
		return zero, operationErr
	}
	return result, nil
}

func executeMandatoryRead[T any](
	f *cliFlags,
	spec readAuditSpec,
	operation func() (T, error),
	resultCount func(T) int,
) (T, error, error) {
	var zero T
	diagnostics := newDelayedReadDiagnostics()
	previousDiagnostics := f.diagnosticOut
	f.diagnosticOut = diagnostics
	releaseDiagnostics := false
	defer func() {
		f.diagnosticOut = previousDiagnostics
		diagnostics.complete(diagnosticWriter(f), releaseDiagnostics)
	}()
	handle, err := beginReadAudit(f, spec)
	if err != nil {
		return zero, nil, err
	}
	if err := authorizeReadAudit(f, spec); err != nil {
		auditErr := persistReadAuditOutcome(handle, completedReadAuditOutcome(0, err), err)
		releaseDiagnostics = auditErr == nil
		return zero, err, auditErr
	}
	result, operationErr := operation()
	count := 0
	if operationErr == nil && resultCount != nil {
		count = resultCount(result)
	}
	if auditErr := persistReadAuditOutcome(
		handle,
		completedReadAuditOutcome(count, operationErr),
		operationErr,
	); auditErr != nil {
		return zero, operationErr, auditErr
	}
	releaseDiagnostics = true
	return result, operationErr, nil
}

func authorizeReadAudit(f *cliFlags, spec readAuditSpec) error {
	authorizations := spec.Authorize
	if len(authorizations) == 0 {
		authorizations = []readAuditAuthorization{{
			ContextName: spec.ContextName,
			Context:     spec.Context,
		}}
	}
	for _, authorization := range authorizations {
		contextName := authorization.ContextName
		if contextName == "" {
			contextName = f.contextName()
		}
		if err := authorizeForContext(f, safety.R0, authorization.Context, "", contextName); err != nil {
			return err
		}
	}
	return nil
}

func runMandatoryBackendRead[T any](
	f *cliFlags,
	action string,
	resourceType string,
	target string,
	request any,
	operation func(cfgov.Backend, cfgovctx.Context) (T, error),
	resultCount func(T) int,
	additionalAuthorizations ...readAuditAuthorization,
) (mandatoryBackendReadResult[T], error) {
	var zero mandatoryBackendReadResult[T]
	contextMeta, contextName, err := resolvedContext(f)
	if err != nil {
		return zero, err
	}
	spec := newReadAuditSpec(action, contextMeta, resourceType, target, request)
	spec.ContextName = contextName
	spec.Authorize = append([]readAuditAuthorization{{
		ContextName: contextName,
		Context:     contextMeta,
	}}, additionalAuthorizations...)
	return runMandatoryRead(
		f,
		spec,
		func() (mandatoryBackendReadResult[T], error) {
			backend, builtContext, buildErr := buildBackendForResolvedContext(f, contextMeta, contextName)
			if buildErr != nil {
				return zero, buildErr
			}
			value, operationErr := operation(backend, builtContext)
			return mandatoryBackendReadResult[T]{
				Backend:     backend,
				Context:     builtContext,
				ContextName: contextName,
				Value:       value,
			}, operationErr
		},
		func(result mandatoryBackendReadResult[T]) int {
			if resultCount == nil {
				return 0
			}
			return resultCount(result.Value)
		},
	)
}
