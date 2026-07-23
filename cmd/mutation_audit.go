package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/lockfile"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

const (
	codeAuditIncomplete        apperrors.ErrorCode = "AUDIT_INCOMPLETE"
	mutationAuditAPIVersion    string              = "cfgov-cli.io/mutation-audit/v1"
	mutationAuditKind          string              = "MutationAuditRecord"
	readAuditKind              string              = "ReadAuditRecord"
	mutationAuditPhaseIntent   string              = "intent"
	mutationAuditPhaseOutcome  string              = "outcome"
	mutationAuditSpoolSuffix   string              = ".outcome-spool"
	mutationAuditSpoolLockBase string              = "queue"
	mutationAuditUncertainMark string              = ".indeterminate"
)

type mutationAuditMetadata struct {
	PayloadFingerprint string `json:"payloadFingerprint,omitempty"`
	PayloadBytes       int    `json:"payloadBytes,omitempty"`
	Revision           string `json:"revision,omitempty"`
	Items              int    `json:"items,omitempty"`
	Creates            int    `json:"creates,omitempty"`
	Updates            int    `json:"updates,omitempty"`
	Deletes            int    `json:"deletes,omitempty"`
}

type mutationAuditOutcome struct {
	Status             string `json:"status"`
	ErrorCode          string `json:"errorCode,omitempty"`
	Succeeded          int    `json:"succeeded,omitempty"`
	Failed             int    `json:"failed,omitempty"`
	Skipped            int    `json:"skipped,omitempty"`
	Uncertain          int    `json:"uncertain,omitempty"`
	Revision           string `json:"revision,omitempty"`
	CompensationStatus string `json:"compensationStatus,omitempty"`
	ResultCount        int    `json:"resultCount,omitempty"`
}

type mutationAuditSpec struct {
	Action      string
	ContextName string
	Context     cfgovctx.Context
	Target      audit.EventTarget
	Metadata    mutationAuditMetadata
	AuditPath   string
	Read        bool
}

type mutationAuditRecord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	audit.Event
	MutationID        string                `json:"mutationId,omitempty"`
	OperationID       string                `json:"operationId,omitempty"`
	Phase             string                `json:"phase"`
	Action            string                `json:"action"`
	TicketFingerprint string                `json:"ticketFingerprint,omitempty"`
	TicketBytes       int                   `json:"ticketBytes,omitempty"`
	ReasonFingerprint string                `json:"reasonFingerprint,omitempty"`
	ReasonBytes       int                   `json:"reasonBytes,omitempty"`
	Metadata          mutationAuditMetadata `json:"metadata,omitempty"`
	Outcome           *mutationAuditOutcome `json:"outcome,omitempty"`
}

type mutationAuditHandle struct {
	f    *cliFlags
	id   string
	path string
	spec mutationAuditSpec
}

type mutationAuditRuntime struct {
	appendRecord   func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error)
	appendOrdinary func(string, any, audit.Options) error
	now            func() time.Time
	random         io.Reader
}

var productionMutationAuditRuntime = mutationAuditRuntime{
	appendRecord: func(path string, record mutationAuditRecord, opts audit.Options) (audit.AppendResult, error) {
		return audit.AppendRecordWithResult(path, record, opts)
	},
	appendOrdinary: audit.AppendRecord,
	now:            func() time.Time { return time.Now().UTC() },
	random:         rand.Reader,
}

var mutationSpoolProcessLocks sync.Map

func beginMutationAudit(f *cliFlags, spec mutationAuditSpec) (*mutationAuditHandle, error) {
	if strings.TrimSpace(spec.Action) == "" {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "mutation audit action is required", nil)
	}
	path := strings.TrimSpace(spec.AuditPath)
	if path == "" {
		var err error
		path, err = configuredAuditPath(f)
		if err != nil {
			return nil, err
		}
	}
	id, err := newMutationID(mutationAuditRuntimeFor(f).random)
	if err != nil {
		return nil, err
	}
	handle := &mutationAuditHandle{f: f, id: id, path: path, spec: spec}
	intentNotCommitted := false
	err = withMutationAuditQueue(path, func(spoolPath string) error {
		if err := verifyMutationSpoolDirectory(spoolPath); err != nil {
			return err
		}
		if err := replayMutationAuditSpoolLocked(f, path, spoolPath); err != nil {
			return err
		}
		record := handle.record(mutationAuditPhaseIntent, nil)
		result, appendErr := appendMutationAuditRecord(f, path, record)
		switch result.State {
		case audit.AppendCommitCommitted:
			if appendErr != nil {
				return auditStateIncompleteError(handle.id, result.State)
			}
			return nil
		case audit.AppendCommitNotCommitted:
			intentNotCommitted = true
			if appendErr != nil {
				return appendErr
			}
			return auditStateIncompleteError(handle.id, result.State)
		case audit.AppendCommitCommittedPostCommitError, audit.AppendCommitIndeterminate:
			return auditStateIncompleteError(handle.id, result.State)
		default:
			return auditStateIncompleteError(handle.id, result.State)
		}
	})
	if intentNotCommitted {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to persist mutation intent", nil)
	}
	if err != nil {
		if apperrors.AsAppError(err).Code == codeAuditIncomplete {
			return nil, err
		}
		return nil, auditIncompleteError("", true)
	}
	return handle, nil
}

func finishMutationAudit(
	handle *mutationAuditHandle,
	outcome mutationAuditOutcome,
	operationErr error,
) error {
	if handle == nil {
		return apperrors.New(apperrors.CodeValidationFailed, "mutation audit handle is required", nil)
	}
	outcome = completedMutationAuditOutcome(outcome, operationErr)
	appendNotCommitted := false
	err := withMutationAuditQueue(handle.path, func(spoolPath string) error {
		if err := verifyMutationSpoolDirectory(spoolPath); err != nil {
			return err
		}
		record := handle.record(mutationAuditPhaseOutcome, &outcome)
		if err := replayMutationAuditSpoolLocked(handle.f, handle.path, spoolPath); err != nil {
			spoolErr := writeMutationSpoolRecord(handle.f, spoolPath, record)
			return auditIncompleteError(handle.id, spoolErr != nil)
		}
		result, appendErr := appendMutationAuditRecord(handle.f, handle.path, record)
		switch result.State {
		case audit.AppendCommitCommitted:
			if appendErr != nil {
				return auditStateIncompleteError(handle.id, result.State)
			}
			return nil
		case audit.AppendCommitNotCommitted:
			appendNotCommitted = true
			return writeMutationSpoolRecord(handle.f, spoolPath, record)
		case audit.AppendCommitCommittedPostCommitError, audit.AppendCommitIndeterminate:
			return auditStateIncompleteError(handle.id, result.State)
		default:
			return auditStateIncompleteError(handle.id, result.State)
		}
	})
	if err != nil {
		if apperrors.AsAppError(err).Code == codeAuditIncomplete {
			return err
		}
		return auditIncompleteError(handle.id, true)
	}
	if appendNotCommitted {
		return auditIncompleteError(handle.id, false)
	}
	return operationErr
}

func completedMutationAuditOutcome(
	outcome mutationAuditOutcome,
	operationErr error,
) mutationAuditOutcome {
	if outcome.Status == "" {
		if operationErr == nil {
			outcome.Status = audit.StatusSuccess
		} else {
			outcome.Status = audit.StatusFailed
		}
	}
	if operationErr != nil && outcome.ErrorCode == "" {
		outcome.ErrorCode = string(apperrors.AsAppError(operationErr).Code)
	}
	if operationErr == nil && outcome.Status == audit.StatusSuccess &&
		outcome.Succeeded == 0 && outcome.Failed == 0 && outcome.Skipped == 0 && outcome.Uncertain == 0 {
		outcome.Succeeded = 1
	}
	return outcome
}

func finishBatchMutationAudit(
	handle *mutationAuditHandle,
	total int,
	succeeded int,
	minimumSkipped int,
	operationErr error,
) error {
	failed := 0
	if operationErr != nil {
		failed = 1
	}
	skipped := total - succeeded - failed
	if skipped < minimumSkipped {
		skipped = minimumSkipped
	}
	status := audit.StatusSuccess
	if operationErr != nil {
		status = audit.StatusFailed
		if succeeded > 0 {
			status = audit.StatusPartialFailed
		}
	}
	return finishMutationAudit(handle, mutationAuditOutcome{
		Status:    status,
		Succeeded: succeeded,
		Failed:    failed,
		Skipped:   skipped,
	}, operationErr)
}

func (handle *mutationAuditHandle) record(phase string, outcome *mutationAuditOutcome) mutationAuditRecord {
	contextName := handle.spec.ContextName
	if contextName == "" {
		contextName = handle.f.contextName()
	}
	kind := mutationAuditKind
	mutationID := handle.id
	operationID := ""
	ticketFingerprint, ticketBytes := "", 0
	reasonFingerprint, reasonBytes := "", 0
	if handle.spec.Read {
		kind = readAuditKind
		mutationID = ""
		operationID = handle.id
	} else {
		ticketFingerprint, ticketBytes = sensitiveAuditFingerprint("ticket", handle.f.Ticket)
		reasonFingerprint, reasonBytes = sensitiveAuditFingerprint("reason", handle.f.Reason)
	}
	status := audit.StatusPending
	if outcome != nil {
		status = outcome.Status
	}
	return mutationAuditRecord{
		APIVersion: mutationAuditAPIVersion,
		Kind:       kind,
		Event: audit.Event{
			Timestamp: mutationAuditRuntimeFor(handle.f).now().UTC(),
			EventType: audit.EventType(handle.spec.Action + "." + phase),
			Operator:  currentOperator(handle.f),
			Context: audit.EventContext{
				Name:      contextName,
				Env:       handle.spec.Context.Env,
				Protected: handle.spec.Context.Protected,
			},
			Target: handle.spec.Target,
			Status: status,
		},
		MutationID:        mutationID,
		OperationID:       operationID,
		Phase:             phase,
		Action:            handle.spec.Action,
		TicketFingerprint: ticketFingerprint,
		TicketBytes:       ticketBytes,
		ReasonFingerprint: reasonFingerprint,
		ReasonBytes:       reasonBytes,
		Metadata:          handle.spec.Metadata,
		Outcome:           outcome,
	}
}

func mutationPayloadMetadata(action string, payload []byte) mutationAuditMetadata {
	return mutationAuditMetadata{
		PayloadFingerprint: mutationAuditFingerprint("payload:"+action, payload),
		PayloadBytes:       len(payload),
	}
}

func mutationValueMetadata(action string, value any) mutationAuditMetadata {
	payload, err := json.Marshal(value)
	if err != nil {
		return mutationAuditMetadata{}
	}
	return mutationPayloadMetadata(action, payload)
}

func beginSchemaMutationAudit(
	f *cliFlags,
	contextMeta cfgovctx.Context,
	resourceType string,
	action string,
	app string,
	items any,
	total int,
	creates int,
	updates int,
	deletes int,
	contextNames ...string,
) (*mutationAuditHandle, error) {
	if creates+updates+deletes == 0 {
		return nil, nil
	}
	eventAction := resourceType + "." + action
	metadata := mutationValueMetadata(eventAction, items)
	metadata.Items = total
	metadata.Creates = creates
	metadata.Updates = updates
	metadata.Deletes = deletes
	contextName := ""
	if len(contextNames) > 0 {
		contextName = contextNames[0]
	}
	return beginMutationAudit(f, mutationAuditSpec{
		Action:      eventAction,
		ContextName: contextName,
		Context:     contextMeta,
		Target: audit.EventTarget{
			App:          app,
			ResourceType: resourceType,
			Resource:     app,
		},
		Metadata: metadata,
	})
}

func sensitiveAuditFingerprint(domain, value string) (string, int) {
	if value == "" {
		return "", 0
	}
	return mutationAuditFingerprint(domain, []byte(value)), len([]byte(value))
}

func mutationAuditFingerprint(domain string, value []byte) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, mutationAuditAPIVersion)
	_, _ = hash.Write([]byte{0})
	_, _ = io.WriteString(hash, domain)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func newMutationID(random io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to generate mutation id", nil)
	}
	return hex.EncodeToString(value), nil
}

func mutationAuditRuntimeFor(f *cliFlags) *mutationAuditRuntime {
	if f != nil && f.mutationAudit != nil {
		return f.mutationAudit
	}
	return &productionMutationAuditRuntime
}

func configuredAuditPath(f *cliFlags) (string, error) {
	if f != nil {
		if path := strings.TrimSpace(f.mutationAuditPath); path != "" {
			return path, nil
		}
	}
	path, err := audit.DefaultPath()
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit path", nil)
	}
	return path, nil
}

func appendQueuedAuditEvent(f *cliFlags, path string, event audit.Event) error {
	return appendQueuedAuditRecord(f, path, func(timestamp time.Time) any {
		event.Timestamp = timestamp
		return event
	})
}

func appendQueuedAuditRecord(
	f *cliFlags,
	path string,
	build func(time.Time) any,
) error {
	if build == nil {
		return apperrors.New(apperrors.CodeValidationFailed, "audit record builder is required", nil)
	}
	return withMutationAuditQueue(path, func(spoolPath string) error {
		if err := verifyMutationSpoolDirectory(spoolPath); err != nil {
			return err
		}
		if err := replayMutationAuditSpoolLocked(f, path, spoolPath); err != nil {
			return err
		}
		runtime := mutationAuditRuntimeFor(f)
		now := time.Now().UTC()
		if runtime.now != nil {
			now = runtime.now().UTC()
		}
		appendRecord := runtime.appendOrdinary
		if appendRecord == nil {
			appendRecord = audit.AppendRecord
		}
		return appendRecord(path, build(now), auditOptions(f))
	})
}

func appendMutationAuditRecord(f *cliFlags, path string, record mutationAuditRecord) (audit.AppendResult, error) {
	runtime := mutationAuditRuntimeFor(f)
	appendRecord := runtime.appendRecord
	if appendRecord == nil {
		appendRecord = func(path string, record mutationAuditRecord, opts audit.Options) (audit.AppendResult, error) {
			return audit.AppendRecordWithResult(path, record, opts)
		}
	}
	return appendRecord(path, record, auditOptions(f))
}

func mutationAuditSpoolPath(auditPath string) string {
	return auditPath + mutationAuditSpoolSuffix
}

func spoolMutationAuditOutcome(f *cliFlags, auditPath string, record mutationAuditRecord) error {
	return withMutationAuditQueue(auditPath, func(spoolPath string) error {
		if err := verifyMutationSpoolDirectory(spoolPath); err != nil {
			return err
		}
		return writeMutationSpoolRecord(f, spoolPath, record)
	})
}

func writeMutationSpoolRecord(_ *cliFlags, spoolPath string, record mutationAuditRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to encode mutation outcome spool", nil)
	}
	sequence, err := nextMutationSpoolSequence(spoolPath)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s.json", sequence, auditRecordID(record))
	finalPath := filepath.Join(spoolPath, name)
	tempPath := finalPath + ".tmp"
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // Path is inside the validated owner-only spool.
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create mutation outcome spool", nil)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(tempPath)
		}
	}()
	if err := secureMutationSpoolFile(tempPath); err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write mutation outcome spool", nil)
	}
	if err := file.Sync(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync mutation outcome spool", nil)
	}
	if err := file.Close(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close mutation outcome spool", nil)
	}
	if err := commitMutationSpoolFile(tempPath, finalPath); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to commit mutation outcome spool", nil)
	}
	complete = true
	return nil
}

func nextMutationSpoolSequence(spoolPath string) (uint64, error) {
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "failed to list mutation outcome spool for sequencing", nil)
	}
	var maximum uint64
	for _, entry := range entries {
		name := entry.Name()
		if name == mutationAuditSpoolLockBase+".lock" {
			continue
		}
		pendingName := strings.TrimSuffix(name, mutationAuditUncertainMark)
		if entry.IsDir() || !validMutationSpoolName(pendingName) {
			return 0, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool contains an unexpected entry", nil)
		}
		separator := strings.IndexByte(pendingName, '-')
		sequence, err := strconv.ParseUint(pendingName[:separator], 10, 64)
		if err != nil {
			return 0, apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool sequence", nil)
		}
		if sequence > maximum {
			maximum = sequence
		}
	}
	if maximum == ^uint64(0) {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool sequence is exhausted", nil)
	}
	return maximum + 1, nil
}

func withMutationAuditQueue(auditPath string, fn func(spoolPath string) error) error {
	if err := ensureMutationAuditDirectory(filepath.Dir(auditPath)); err != nil {
		return err
	}
	spoolPath := mutationAuditSpoolPath(auditPath)
	if err := ensureMutationSpoolDirectory(spoolPath); err != nil {
		return err
	}
	return withMutationSpoolLock(spoolPath, func() error {
		if err := verifyMutationSpoolDirectory(spoolPath); err != nil {
			return err
		}
		return fn(spoolPath)
	})
}

func ensureMutationAuditDirectory(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return apperrors.New(apperrors.CodeLocalIOError, "mutation audit directory must be a real directory", nil)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect mutation audit directory", nil)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return apperrors.New(apperrors.CodeLocalIOError, "mutation audit directory has no existing ancestor", nil)
	}
	if err := ensureMutationAuditDirectory(parent); err != nil {
		return err
	}
	return createPrivateMutationAuditDirectory(path)
}

func replayMutationAuditSpoolLocked(f *cliFlags, auditPath, spoolPath string) error { //nolint:gocyclo // Every durable append state has a distinct replay/no-replay transition.
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to list mutation outcome spool", nil)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == mutationAuditSpoolLockBase+".lock" {
			continue
		}
		if strings.HasSuffix(name, mutationAuditUncertainMark) {
			pendingName := strings.TrimSuffix(name, mutationAuditUncertainMark)
			if entry.IsDir() || !validMutationSpoolName(pendingName) {
				return apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool contains an unexpected entry", nil)
			}
			return auditStateIncompleteError(mutationIDFromSpoolName(pendingName), audit.AppendCommitIndeterminate)
		}
		if entry.IsDir() || !validMutationSpoolName(name) {
			return apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool contains an unexpected entry", nil)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(spoolPath, name)
		record, err := readMutationSpoolRecord(path)
		if err != nil {
			return err
		}
		result, appendErr := appendMutationAuditRecord(f, auditPath, record)
		switch result.State {
		case audit.AppendCommitCommitted:
			if appendErr != nil {
				return auditStateIncompleteError(auditRecordID(record), result.State)
			}
		case audit.AppendCommitCommittedPostCommitError:
			if err := removeReplayedMutationSpool(path, spoolPath); err != nil {
				return err
			}
			return auditStateIncompleteError(auditRecordID(record), result.State)
		case audit.AppendCommitIndeterminate:
			if err := markMutationSpoolIndeterminate(path, spoolPath); err != nil {
				return auditIncompleteError(auditRecordID(record), true)
			}
			return auditStateIncompleteError(auditRecordID(record), result.State)
		case audit.AppendCommitNotCommitted:
			return auditIncompleteError(auditRecordID(record), false)
		default:
			return auditStateIncompleteError(auditRecordID(record), result.State)
		}
		if err := removeReplayedMutationSpool(path, spoolPath); err != nil {
			return err
		}
	}
	return nil
}

func removeReplayedMutationSpool(path, spoolPath string) error {
	if err := os.Remove(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to remove replayed mutation outcome spool", nil)
	}
	return syncMutationSpoolDirectory(spoolPath)
}

func markMutationSpoolIndeterminate(path, spoolPath string) error {
	if err := os.Rename(path, path+mutationAuditUncertainMark); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to quarantine indeterminate mutation outcome spool", nil)
	}
	return syncMutationSpoolDirectory(spoolPath)
}

func mutationIDFromSpoolName(name string) string {
	separator := strings.IndexByte(name, '-')
	if separator < 0 {
		return ""
	}
	return strings.TrimSuffix(name[separator+1:], ".json")
}

func withMutationSpoolLock(spoolPath string, fn func() error) (err error) {
	lockValue, _ := mutationSpoolProcessLocks.LoadOrStore(filepath.Clean(spoolPath), &sync.Mutex{})
	processLock, ok := lockValue.(*sync.Mutex)
	if !ok {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool lock state", nil)
	}
	processLock.Lock()
	defer processLock.Unlock()

	lock := lockfile.New(filepath.Join(spoolPath, mutationAuditSpoolLockBase))
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() {
		if releaseErr := lock.Release(); err == nil && releaseErr != nil {
			err = apperrors.New(apperrors.CodeLocalIOError, "failed to release mutation outcome spool lock", nil)
		}
	}()
	return fn()
}

func validMutationSpoolName(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(name, ".json"), "-")
	if len(parts) != 2 || len(parts[0]) != 20 || len(parts[1]) != 32 {
		return false
	}
	if _, err := strconv.ParseUint(parts[0], 10, 64); err != nil {
		return false
	}
	_, err := hex.DecodeString(parts[1])
	return err == nil
}

func readMutationSpoolRecord(path string) (mutationAuditRecord, error) {
	var record mutationAuditRecord
	if err := verifyMutationSpoolFile(path); err != nil {
		return record, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect mutation outcome spool file", nil)
	}
	// Windows loads a FileInfo's stable file ID lazily. Force that load before
	// opening the path so SameFile cannot observe a replacement as the original.
	if !os.SameFile(before, before) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to identify mutation outcome spool file", nil)
	}
	file, err := os.Open(path) //nolint:gosec // Path is strictly named inside a validated owner-only spool.
	if err != nil {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to open mutation outcome spool file", nil)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool file changed while opening", nil)
	}
	data, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to read mutation outcome spool file", nil)
	}
	if hasDuplicateTopLevelJSONKey(bytes.TrimSpace(data)) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool has duplicate fields", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool record", nil)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool contains trailing data", nil)
	}
	if err := validateMutationSpoolRecord(record); err != nil {
		return mutationAuditRecord{}, err
	}
	return record, nil
}

func validateMutationSpoolRecord(record mutationAuditRecord) error { //nolint:gocyclo // The complete fail-closed spool schema is checked in one predicate.
	recordID := auditRecordID(record)
	isMutation := record.Kind == mutationAuditKind
	isRead := record.Kind == readAuditKind
	if record.APIVersion != mutationAuditAPIVersion ||
		(!isMutation && !isRead) ||
		record.Phase != mutationAuditPhaseOutcome ||
		record.Action == "" ||
		len(record.Action) > 256 ||
		len(recordID) != 32 ||
		(isMutation && (record.MutationID == "" || record.OperationID != "")) ||
		(isRead && (record.OperationID == "" || record.MutationID != "")) ||
		record.Outcome == nil ||
		record.Timestamp.IsZero() ||
		record.EventType != audit.EventType(record.Action+"."+mutationAuditPhaseOutcome) ||
		record.Status != record.Outcome.Status ||
		record.Ticket != "" ||
		record.Reason != "" ||
		record.Diff != "" ||
		record.Error != nil ||
		record.RoleChange != nil ||
		record.AuditPrune != nil ||
		record.BackupPrune != nil ||
		record.RoleFetch != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool record", nil)
	}
	if recordID != strings.ToLower(recordID) {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool record id", nil)
	}
	if _, err := hex.DecodeString(recordID); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool record id", nil)
	}
	if !validOptionalMutationAuditFingerprint(record.TicketFingerprint, record.TicketBytes) ||
		!validOptionalMutationAuditFingerprint(record.ReasonFingerprint, record.ReasonBytes) ||
		!validOptionalMutationAuditFingerprint(record.Metadata.PayloadFingerprint, record.Metadata.PayloadBytes) {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool fingerprint", nil)
	}
	if record.Metadata.Items < 0 ||
		record.Metadata.Items > 1_000_000_000 ||
		record.Metadata.Creates < 0 ||
		record.Metadata.Updates < 0 ||
		record.Metadata.Deletes < 0 ||
		record.Outcome.Succeeded < 0 ||
		record.Outcome.Failed < 0 ||
		record.Outcome.Skipped < 0 ||
		record.Outcome.Uncertain < 0 ||
		record.Outcome.ResultCount < 0 ||
		record.Outcome.ResultCount > 1_000_000_000 ||
		len(record.Metadata.Revision) > 256 ||
		len(record.Outcome.Revision) > 256 ||
		len(record.Outcome.ErrorCode) > 128 ||
		!validCredentialCompensationStatus(record.Outcome.CompensationStatus) ||
		len(record.Operator) > 512 ||
		len(record.Context.Name) > 512 ||
		len(record.Context.Env) > 512 ||
		len(record.Target.App) > 512 ||
		len(record.Target.ResourceType) > 512 ||
		len(record.Target.Resource) > 512 {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool fields", nil)
	}
	if isRead &&
		(record.TicketFingerprint != "" ||
			record.TicketBytes != 0 ||
			record.ReasonFingerprint != "" ||
			record.ReasonBytes != 0 ||
			record.Metadata.PayloadBytes > 1_000_000_000 ||
			record.Metadata.Revision != "" ||
			record.Metadata.Creates != 0 ||
			record.Metadata.Updates != 0 ||
			record.Metadata.Deletes != 0 ||
			record.Outcome.Revision != "" ||
			record.Outcome.CompensationStatus != "" ||
			record.Outcome.Uncertain != 0 ||
			record.Target.App != "" ||
			record.Target.ResourceType == "" ||
			!validReadAuditTarget(record.Target.Resource)) {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid read outcome spool record", nil)
	}
	if isMutation && record.Outcome.ResultCount != 0 {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome result count", nil)
	}
	total := uint64(record.Outcome.Succeeded) +
		uint64(record.Outcome.Failed) +
		uint64(record.Outcome.Skipped) +
		uint64(record.Outcome.Uncertain)
	validStatus := record.Outcome.Status == audit.StatusSuccess ||
		record.Outcome.Status == audit.StatusFailed ||
		record.Outcome.Status == audit.StatusPartialFailed
	if !validStatus ||
		total > 1_000_000_000 ||
		(record.Metadata.Items > 0 && total > uint64(record.Metadata.Items)) ||
		(record.Outcome.Status == audit.StatusSuccess &&
			(record.Outcome.Failed != 0 || record.Outcome.Uncertain != 0 || record.Outcome.CompensationStatus != "")) ||
		(record.Outcome.CompensationStatus == "succeeded" && record.Outcome.Uncertain != 0) ||
		(record.Outcome.CompensationStatus == "incomplete" && record.Outcome.Uncertain == 0) ||
		(record.Outcome.CompensationStatus == "not-safe" &&
			record.Outcome.Succeeded == 0 && record.Outcome.Uncertain == 0) ||
		(record.Outcome.Status != audit.StatusSuccess && record.Outcome.ErrorCode == "") {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool outcome", nil)
	}
	return nil
}

func auditRecordID(record mutationAuditRecord) string {
	if record.Kind == readAuditKind {
		return record.OperationID
	}
	return record.MutationID
}

func validReadAuditTarget(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha256:")
	if encoded != strings.ToLower(encoded) {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size
}

func validCredentialCompensationStatus(status string) bool {
	return status == "" || status == "succeeded" || status == "incomplete" || status == "not-safe"
}

func validOptionalMutationAuditFingerprint(fingerprint string, size int) bool {
	if fingerprint == "" || size == 0 {
		return fingerprint == "" && size == 0
	}
	if size < 0 ||
		len(fingerprint) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(fingerprint, "sha256:") {
		return false
	}
	encoded := strings.TrimPrefix(fingerprint, "sha256:")
	if encoded != strings.ToLower(encoded) {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size
}

func hasDuplicateTopLevelJSONKey(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return false
	}
	seen := make([]string, 0)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok {
			return false
		}
		for _, existing := range seen {
			if strings.EqualFold(existing, key) {
				return true
			}
		}
		seen = append(seen, key)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	return false
}

func auditIncompleteError(mutationID string, spoolFailed bool) error {
	message := "mutation outcome audit is incomplete"
	if spoolFailed {
		message = "mutation outcome audit is incomplete and durable spooling failed"
	}
	suggestion := "Resolve audit storage before another mutation; a later mutation replays durable outcomes automatically."
	if mutationID != "" {
		suggestion = fmt.Sprintf(
			"Do not retry blindly. Check mutationId %s, resolve audit storage, then run a mutation to replay durable outcomes.",
			mutationID,
		)
	}
	return apperrors.New(codeAuditIncomplete, message, nil).WithSuggestion(suggestion)
}

func auditStateIncompleteError(mutationID string, state audit.AppendCommitState) error {
	message := fmt.Sprintf("mutation audit append state is %q", state)
	if state == "" {
		message = "mutation audit append returned an unknown commit state"
	}
	suggestion := "Resolve audit integrity or lock cleanup before another mutation; no replay spool was created because the record may already exist."
	if mutationID != "" {
		suggestion = fmt.Sprintf(
			"Do not retry blindly. Check mutationId %s and resolve audit integrity or lock cleanup; no replay spool was created because the record may already exist.",
			mutationID,
		)
	}
	return apperrors.New(codeAuditIncomplete, message, nil).WithSuggestion(suggestion)
}
