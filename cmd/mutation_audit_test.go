package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestMutationAuditOutcomeFailureSpoolsSanitizedAndReplaysBeforeNextIntent(t *testing.T) {
	const (
		ticketSentinel  = "TICKET-SENSITIVE-SENTINEL"
		reasonSentinel  = "REASON-SENSITIVE-SENTINEL"
		payloadSentinel = "CONFIG-BODY-SENSITIVE-SENTINEL"
		errorSentinel   = "ERROR-SENSITIVE-SENTINEL"
	)
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	f := mutationAuditTestFlags()
	f.Ticket = ticketSentinel
	f.Reason = reasonSentinel
	appendCalls := 0
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(path string, record mutationAuditRecord, options audit.Options) (audit.AppendResult, error) {
			appendCalls++
			if appendCalls == 2 {
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome append failure")
			}
			return audit.AppendRecordWithResult(path, record, options)
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)),
	}

	metadata := mutationPayloadMetadata("config.write", []byte(payloadSentinel))
	metadata.Items = 1
	metadata.Updates = 1
	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "config.write",
		Target:    audit.EventTarget{ResourceType: "config", Resource: "safe-key"},
		Metadata:  metadata,
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("beginMutationAudit() error = %v", err)
	}
	operationErr := apperrors.New(apperrors.CodeNetworkError, errorSentinel, nil)
	err = finishMutationAudit(handle, mutationAuditOutcome{}, operationErr)
	if got := apperrors.AsAppError(err).Code; got != codeAuditIncomplete {
		t.Fatalf("finishMutationAudit() code = %s, want %s (err=%v)", got, codeAuditIncomplete, err)
	}

	assertFilesExcludeSentinels(t, []string{auditPath, mutationAuditSpoolPath(auditPath)}, []string{
		ticketSentinel,
		reasonSentinel,
		payloadSentinel,
		errorSentinel,
	})

	var replayed []mutationAuditRecord
	f.mutationAudit.appendRecord = func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
		replayed = append(replayed, record)
		return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
	}
	next, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "config.delete",
		Target:    audit.EventTarget{ResourceType: "config", Resource: "safe-key"},
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("next beginMutationAudit() error = %v", err)
	}
	if len(replayed) != 2 {
		t.Fatalf("replayed records = %d, want outcome then intent", len(replayed))
	}
	if replayed[0].Phase != mutationAuditPhaseOutcome || replayed[0].MutationID != handle.id {
		t.Fatalf("first replayed record = phase %q mutationId %q, want prior outcome %q", replayed[0].Phase, replayed[0].MutationID, handle.id)
	}
	if replayed[1].Phase != mutationAuditPhaseIntent || replayed[1].MutationID != next.id {
		t.Fatalf("second replayed record = phase %q mutationId %q, want next intent %q", replayed[1].Phase, replayed[1].MutationID, next.id)
	}
	entries, err := os.ReadDir(mutationAuditSpoolPath(auditPath))
	if err != nil {
		t.Fatalf("ReadDir(spool) error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("replayed spool record still exists: %s", entry.Name())
		}
	}
}

func TestMutationAuditFinishReplaysPendingOutcomeBeforeCurrentOutcome(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	random := append(
		bytes.Repeat([]byte{0x31}, 16),
		bytes.Repeat([]byte{0x32}, 16)...,
	)
	var (
		failedMutationID string
		failedOnce       bool
		appended         []mutationAuditRecord
	)
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			if record.MutationID == failedMutationID &&
				record.Phase == mutationAuditPhaseOutcome &&
				!failedOnce {
				failedOnce = true
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome append failure")
			}
			appended = append(appended, record)
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(random),
	}

	first, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "config.write",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("first beginMutationAudit() error = %v", err)
	}
	second, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "config.delete",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("second beginMutationAudit() error = %v", err)
	}
	failedMutationID = first.id
	if err := finishMutationAudit(first, mutationAuditOutcome{Succeeded: 1}, nil); apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("first finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
	}

	appended = nil
	if err := finishMutationAudit(second, mutationAuditOutcome{Succeeded: 1}, nil); err != nil {
		t.Fatalf("second finishMutationAudit() error = %v", err)
	}
	if len(appended) != 2 {
		t.Fatalf("appended records = %d, want replayed outcome then current outcome", len(appended))
	}
	if appended[0].MutationID != first.id || appended[0].Phase != mutationAuditPhaseOutcome {
		t.Fatalf("first appended record = %#v, want replayed outcome for %s", appended[0], first.id)
	}
	if appended[1].MutationID != second.id || appended[1].Phase != mutationAuditPhaseOutcome {
		t.Fatalf("second appended record = %#v, want current outcome for %s", appended[1], second.id)
	}
}

func TestQueuedR0AuditReplaysPendingOutcomeBeforeLaterTimestamp(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	baseTime := time.Unix(1_700_000_000, 0).UTC()
	nowCall := 0
	order := make([]string, 0, 2)
	var replayedOutcome mutationAuditRecord
	var ordinary audit.Event
	failedOnce := false
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			if record.Phase == mutationAuditPhaseOutcome && !failedOnce {
				failedOnce = true
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome append failure")
			}
			if record.Phase == mutationAuditPhaseOutcome {
				order = append(order, "outcome")
				replayedOutcome = record
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		appendOrdinary: func(_ string, record any, _ audit.Options) error {
			event, ok := record.(audit.Event)
			if !ok {
				t.Fatalf("ordinary audit record type = %T, want audit.Event", record)
			}
			order = append(order, "r0")
			ordinary = event
			return nil
		},
		now: func() time.Time {
			value := baseTime.Add(time.Duration(nowCall) * time.Second)
			nowCall++
			return value
		},
		random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 16)),
	}

	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "config.write",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("beginMutationAudit() error = %v", err)
	}
	if err := finishMutationAudit(handle, mutationAuditOutcome{Succeeded: 1}, nil); apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
	}
	if err := appendQueuedAuditEvent(f, auditPath, audit.Event{
		EventType: "config.get",
		Status:    audit.StatusSuccess,
	}); err != nil {
		t.Fatalf("appendQueuedAuditEvent() error = %v", err)
	}

	if got := strings.Join(order, ","); got != "outcome,r0" {
		t.Fatalf("append order = %q, want outcome,r0", got)
	}
	if !replayedOutcome.Timestamp.Before(ordinary.Timestamp) {
		t.Fatalf(
			"timestamps = replayed %s, ordinary %s; want replayed before ordinary",
			replayedOutcome.Timestamp,
			ordinary.Timestamp,
		)
	}
}

func TestMutationAuditIntentFailureStopsBeforeTarget(t *testing.T) {
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected intent failure")
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x24}, 16)),
	}
	targetCalls := 0
	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "namespace.create",
		Target:    audit.EventTarget{ResourceType: "namespace", Resource: "safe"},
		AuditPath: filepath.Join(t.TempDir(), "audit.log"),
	})
	if err == nil {
		targetCalls++
		_ = finishMutationAudit(handle, mutationAuditOutcome{}, nil)
	}
	if err == nil {
		t.Fatal("beginMutationAudit() error = nil, want intent persistence failure")
	}
	if targetCalls != 0 {
		t.Fatalf("target calls = %d, want 0", targetCalls)
	}
}

func TestMutationAuditCommittedPostCommitIntentFailureDoesNotSpoolDuplicate(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	var appended []mutationAuditRecord
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			appended = append(appended, record)
			return audit.AppendResult{State: audit.AppendCommitCommittedPostCommitError}, errors.New("injected checkpoint failure")
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x25}, 16)),
	}

	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "namespace.create",
		AuditPath: auditPath,
	})
	if handle != nil {
		t.Fatalf("beginMutationAudit() handle = %#v, want nil", handle)
	}
	if got := apperrors.AsAppError(err).Code; got != codeAuditIncomplete {
		t.Fatalf("beginMutationAudit() code = %s, want %s (err=%v)", got, codeAuditIncomplete, err)
	}
	if len(appended) != 1 || appended[0].Phase != mutationAuditPhaseIntent {
		t.Fatalf("appended records = %#v, want one intent", appended)
	}
	entries, err := os.ReadDir(mutationAuditSpoolPath(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), mutationAuditUncertainMark) {
			t.Fatalf("committed intent was spooled and could be duplicated: %s", entry.Name())
		}
	}
}

func TestMutationAuditOutcomeUncertainStatesDoNotCreateReplayableDuplicates(t *testing.T) {
	for _, state := range []audit.AppendCommitState{
		audit.AppendCommitCommittedPostCommitError,
		audit.AppendCommitIndeterminate,
	} {
		t.Run(string(state), func(t *testing.T) {
			root := t.TempDir()
			prepareMutationAuditTestParent(t, root)
			auditPath := filepath.Join(root, "audit.log")
			calls := 0
			f := mutationAuditTestFlags()
			f.mutationAudit = &mutationAuditRuntime{
				appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
					calls++
					if calls == 1 {
						return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
					}
					return audit.AppendResult{State: state}, errors.New("injected uncertain outcome append")
				},
				now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
				random: bytes.NewReader(bytes.Repeat([]byte{0x26}, 16)),
			}
			handle, err := beginMutationAudit(f, mutationAuditSpec{Action: "config.write", AuditPath: auditPath})
			if err != nil {
				t.Fatalf("beginMutationAudit() error = %v", err)
			}
			if err := finishMutationAudit(handle, mutationAuditOutcome{Succeeded: 1}, nil); apperrors.AsAppError(err).Code != codeAuditIncomplete {
				t.Fatalf("finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
			}
			entries, err := os.ReadDir(mutationAuditSpoolPath(auditPath))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), mutationAuditUncertainMark) {
					t.Fatalf("uncertain committed state created replayable evidence: %s", entry.Name())
				}
			}
		})
	}
}

func TestMutationAuditIndeterminateReplayIsQuarantinedAndNotRetried(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	spoolPath := mutationAuditSpoolPath(auditPath)
	if err := ensureMutationSpoolDirectory(spoolPath); err != nil {
		t.Fatal(err)
	}
	record := mutationAuditTestOutcomeRecord("27272727272727272727272727272727")
	if err := writeMutationSpoolRecord(nil, spoolPath, record); err != nil {
		t.Fatal(err)
	}
	appendCalls := 0
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			appendCalls++
			return audit.AppendResult{State: audit.AppendCommitIndeterminate}, errors.New("injected indeterminate replay")
		},
		now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	for attempt := 0; attempt < 2; attempt++ {
		err := withMutationAuditQueue(auditPath, func(path string) error {
			return replayMutationAuditSpoolLocked(f, auditPath, path)
		})
		if apperrors.AsAppError(err).Code != codeAuditIncomplete {
			t.Fatalf("replay attempt %d error = %v, want %s", attempt+1, err, codeAuditIncomplete)
		}
	}
	if appendCalls != 1 {
		t.Fatalf("append calls = %d, want exactly one indeterminate attempt", appendCalls)
	}
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		t.Fatal(err)
	}
	foundMarker := false
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), mutationAuditUncertainMark) {
			foundMarker = true
		}
	}
	if !foundMarker {
		t.Fatal("indeterminate replay marker was not preserved")
	}
}

func TestMutationAuditFinishPreservesOutcomeBehindIndeterminateReplay(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	spoolPath := mutationAuditSpoolPath(auditPath)
	if err := ensureMutationSpoolDirectory(spoolPath); err != nil {
		t.Fatal(err)
	}
	prior := mutationAuditTestOutcomeRecord("28282828282828282828282828282828")
	if err := writeMutationSpoolRecord(nil, spoolPath, prior); err != nil {
		t.Fatal(err)
	}
	appendCalls := 0
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			appendCalls++
			return audit.AppendResult{State: audit.AppendCommitIndeterminate}, errors.New("injected indeterminate replay")
		},
		now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	handle := &mutationAuditHandle{
		f:    f,
		id:   "29292929292929292929292929292929",
		path: auditPath,
		spec: mutationAuditSpec{Action: "config.write"},
	}
	if err := finishMutationAudit(handle, mutationAuditOutcome{Succeeded: 1}, nil); apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
	}
	if appendCalls != 1 {
		t.Fatalf("append calls = %d, want one replay attempt", appendCalls)
	}
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		t.Fatal(err)
	}
	markerCount := 0
	pendingCount := 0
	for _, entry := range entries {
		switch {
		case strings.HasSuffix(entry.Name(), mutationAuditUncertainMark):
			markerCount++
		case strings.HasSuffix(entry.Name(), ".json"):
			pendingCount++
		}
	}
	if markerCount != 1 || pendingCount != 1 {
		t.Fatalf("spool entries = %v, want one marker and one later pending outcome", entries)
	}
}

func TestMutationAuditReplayRejectsUnexpectedSpoolEntryBeforeIntent(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	spoolPath := mutationAuditSpoolPath(auditPath)
	if err := ensureMutationSpoolDirectory(spoolPath); err != nil {
		t.Fatalf("ensureMutationSpoolDirectory() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(spoolPath, "unexpected"), []byte("unsafe"), 0o600); err != nil {
		t.Fatalf("WriteFile(unexpected) error = %v", err)
	}
	appendCalls := 0
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			appendCalls++
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x11}, 16)),
	}
	_, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "config.write",
		AuditPath: auditPath,
	})
	if got := apperrors.AsAppError(err).Code; got != codeAuditIncomplete {
		t.Fatalf("beginMutationAudit() code = %s, want %s (err=%v)", got, codeAuditIncomplete, err)
	}
	if appendCalls != 0 {
		t.Fatalf("append calls = %d, want 0 before unsafe spool is resolved", appendCalls)
	}
}

func TestMutationAuditConcurrentSpoolWritersAreSerialized(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	spoolPath := mutationAuditSpoolPath(auditPath)
	f := mutationAuditTestFlags()
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x33}, 16)),
	}
	records := []mutationAuditRecord{
		mutationAuditTestOutcomeRecord("00000000000000000000000000000001"),
		mutationAuditTestOutcomeRecord("00000000000000000000000000000002"),
	}
	var wait sync.WaitGroup
	errorsByWriter := make([]error, len(records))
	for index := range records {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByWriter[index] = spoolMutationAuditOutcome(f, auditPath, records[index])
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByWriter {
		if err != nil {
			t.Fatalf("spool writer %d error = %v", index, err)
		}
	}
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		t.Fatalf("ReadDir(spool) error = %v", err)
	}
	jsonFiles := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			jsonFiles++
			if err := verifyMutationSpoolFile(filepath.Join(spoolPath, entry.Name())); err != nil {
				t.Fatalf("verifyMutationSpoolFile(%s) error = %v", entry.Name(), err)
			}
		}
	}
	if jsonFiles != len(records) {
		t.Fatalf("spooled JSON files = %d, want %d", jsonFiles, len(records))
	}
}

func TestMutationSpoolSequencePreservesLockedWriteOrder(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	f := mutationAuditTestFlags()
	for index, id := range []string{
		"11111111111111111111111111111111",
		"22222222222222222222222222222222",
	} {
		record := mutationAuditTestOutcomeRecord(id)
		if err := spoolMutationAuditOutcome(f, auditPath, record); err != nil {
			t.Fatalf("spool write %d: %v", index, err)
		}
	}
	entries, err := os.ReadDir(mutationAuditSpoolPath(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, 2)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	if len(names) != 2 ||
		!strings.HasPrefix(names[0], "00000000000000000001-1111") ||
		!strings.HasPrefix(names[1], "00000000000000000002-2222") {
		t.Fatalf("spool order = %v", names)
	}
}

func TestValidateMutationSpoolRecordRejectsForgedFields(t *testing.T) {
	base := mutationAuditTestOutcomeRecord("00000000000000000000000000000001")
	base.Metadata.Items = 1
	tests := []struct {
		name   string
		mutate func(*mutationAuditRecord)
	}{
		{
			name: "raw fingerprint",
			mutate: func(record *mutationAuditRecord) {
				record.TicketFingerprint = "ticket=secret"
				record.TicketBytes = 13
			},
		},
		{
			name: "negative count",
			mutate: func(record *mutationAuditRecord) {
				record.Outcome.Succeeded = -1
			},
		},
		{
			name: "event type mismatch",
			mutate: func(record *mutationAuditRecord) {
				record.EventType = "other.outcome"
			},
		},
		{
			name: "status mismatch",
			mutate: func(record *mutationAuditRecord) {
				record.Status = audit.StatusFailed
			},
		},
		{
			name: "failed without error code",
			mutate: func(record *mutationAuditRecord) {
				record.Status = audit.StatusFailed
				record.Outcome.Status = audit.StatusFailed
			},
		},
		{
			name: "outcome exceeds item count",
			mutate: func(record *mutationAuditRecord) {
				record.Outcome.Succeeded = 2
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := base
			outcome := *base.Outcome
			record.Outcome = &outcome
			tt.mutate(&record)
			if err := validateMutationSpoolRecord(record); err == nil {
				t.Fatal("validateMutationSpoolRecord() error = nil")
			}
		})
	}
}

func TestMutationAuditOutcomeFallbackPrecedesConcurrentIntent(t *testing.T) {
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	auditPath := filepath.Join(root, "audit.log")
	const priorID = "11111111111111111111111111111111"

	outcomeAppendStarted := make(chan struct{})
	releaseOutcomeAppend := make(chan struct{})
	nextIntentAppended := make(chan struct{})
	var callsMu sync.Mutex
	var calls []string
	firstOutcomeAttempt := true
	runtime := &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			callsMu.Lock()
			calls = append(calls, record.MutationID+"/"+record.Phase)
			blockOutcome := record.MutationID == priorID &&
				record.Phase == mutationAuditPhaseOutcome &&
				firstOutcomeAttempt
			if blockOutcome {
				firstOutcomeAttempt = false
			}
			callsMu.Unlock()
			if blockOutcome {
				close(outcomeAppendStarted)
				<-releaseOutcomeAppend
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected outcome append failure")
			}
			if record.MutationID != priorID && record.Phase == mutationAuditPhaseIntent {
				close(nextIntentAppended)
			}
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x22}, 16)),
	}
	f := mutationAuditTestFlags()
	f.mutationAudit = runtime
	prior := &mutationAuditHandle{
		f:    f,
		id:   priorID,
		path: auditPath,
		spec: mutationAuditSpec{Action: "config.write"},
	}

	finishDone := make(chan error, 1)
	go func() {
		finishDone <- finishMutationAudit(prior, mutationAuditOutcome{Succeeded: 1}, nil)
	}()
	<-outcomeAppendStarted

	beginDone := make(chan error, 1)
	go func() {
		_, err := beginMutationAudit(f, mutationAuditSpec{
			Action:    "config.delete",
			AuditPath: auditPath,
		})
		beginDone <- err
	}()

	intentRanEarly := false
	select {
	case <-nextIntentAppended:
		intentRanEarly = true
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseOutcomeAppend)

	if err := <-finishDone; apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
	}
	if err := <-beginDone; err != nil {
		t.Fatalf("beginMutationAudit() error = %v", err)
	}
	if intentRanEarly {
		t.Fatal("concurrent intent appended before the prior failed outcome was durably spooled")
	}
	callsMu.Lock()
	gotCalls := append([]string(nil), calls...)
	callsMu.Unlock()
	if len(gotCalls) != 3 ||
		gotCalls[0] != priorID+"/"+mutationAuditPhaseOutcome ||
		gotCalls[1] != priorID+"/"+mutationAuditPhaseOutcome ||
		!strings.HasSuffix(gotCalls[2], "/"+mutationAuditPhaseIntent) {
		t.Fatalf("append order = %v, want failed outcome, replayed outcome, then next intent", gotCalls)
	}
}

func TestMutationAuditFingerprintIsDomainSeparated(t *testing.T) {
	value := []byte("same-sensitive-value")
	if mutationAuditFingerprint("ticket", value) == mutationAuditFingerprint("reason", value) {
		t.Fatal("ticket and reason fingerprints must use different domains")
	}
}

func TestHistoricalAuditOutputHidesLegacySensitiveFields(t *testing.T) {
	event := audit.Event{
		EventType: "config.write",
		Ticket:    "LEGACY-TICKET-SENTINEL",
		Reason:    "LEGACY-REASON-SENTINEL",
		Diff:      "LEGACY-CONFIG-BODY-SENTINEL",
		Error:     &audit.EventError{Code: string(apperrors.CodeNetworkError), Message: "LEGACY-ERROR-SENTINEL"},
	}
	sanitized, ok := auditEventForOutput(event).(audit.Event)
	if !ok {
		t.Fatalf("auditEventForOutput() type = %T, want audit.Event", auditEventForOutput(event))
	}
	if sanitized.Ticket != "" || sanitized.Reason != "" || sanitized.Diff != "" {
		t.Fatalf("historical sensitive fields were not removed: %#v", sanitized)
	}
	if sanitized.Error == nil || sanitized.Error.Code != string(apperrors.CodeNetworkError) || sanitized.Error.Message != "" {
		t.Fatalf("historical error = %#v, want code only", sanitized.Error)
	}
}

func TestCapabilitiesAdvertiseMutationAuditContract(t *testing.T) {
	capabilities := buildCapabilities(newDefaultFlags(), cfgov.Capabilities{})
	if !capabilities.Domain.Features.MutationIntent ||
		!capabilities.Domain.Features.DurableOutcomeSpool ||
		!capabilities.Domain.Features.FingerprintOnlyAudit {
		t.Fatalf("mutation audit features = %#v, want all enabled", capabilities.Domain.Features)
	}
	if !containsAuditString(capabilities.Supported.AuditAPIVersions, mutationAuditAPIVersion) {
		t.Fatalf("audit API versions = %v, want %s", capabilities.Supported.AuditAPIVersions, mutationAuditAPIVersion)
	}
	if !containsAuditString(capabilities.Domain.ErrorCodes, string(codeAuditIncomplete)) {
		t.Fatalf("error codes = %v, want %s", capabilities.Domain.ErrorCodes, codeAuditIncomplete)
	}
	if !containsAuditString(capabilities.Domain.Kinds, mutationAuditKind) {
		t.Fatalf("kinds = %v, want %s", capabilities.Domain.Kinds, mutationAuditKind)
	}
}

func mutationAuditTestFlags() *cliFlags {
	f := newDefaultFlags()
	f.Context = "test"
	f.trustedOperator = "tester@host"
	return f
}

func containsAuditString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mutationAuditTestOutcomeRecord(id string) mutationAuditRecord {
	return mutationAuditRecord{
		APIVersion: mutationAuditAPIVersion,
		Kind:       mutationAuditKind,
		Event: audit.Event{
			Timestamp: time.Unix(1_700_000_000, 0).UTC(),
			EventType: "config.write.outcome",
			Status:    audit.StatusSuccess,
			Target:    audit.EventTarget{ResourceType: "config", Resource: "safe"},
		},
		MutationID: id,
		Phase:      mutationAuditPhaseOutcome,
		Action:     "config.write",
		Outcome:    &mutationAuditOutcome{Status: audit.StatusSuccess, Succeeded: 1},
	}
}

func assertFilesExcludeSentinels(t *testing.T, roots []string, sentinels []string) {
	t.Helper()
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", root, err)
		}
		paths := []string{root}
		if info.IsDir() {
			paths = nil
			err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr == nil && !entry.IsDir() {
					paths = append(paths, path)
				}
				return walkErr
			})
			if err != nil {
				t.Fatalf("WalkDir(%s) error = %v", root, err)
			}
		}
		for _, path := range paths {
			data, err := os.ReadFile(path) //nolint:gosec // Test reads files created under t.TempDir.
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", path, err)
			}
			for _, sentinel := range sentinels {
				if bytes.Contains(data, []byte(sentinel)) {
					t.Fatalf("sensitive sentinel %q leaked into %s", sentinel, path)
				}
			}
		}
	}
}
