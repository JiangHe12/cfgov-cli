package cmd

import (
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/audit"
)

func TestAuditVerifyHasProblemsCoversCoreV2Signals(t *testing.T) {
	tests := []audit.VerifyResult{
		{Malformed: 1},
		{SchemaErrors: 1},
		{TimestampOrderViolations: 1},
		{IntegrityErrors: 1},
		{SequenceViolations: 1},
		{CheckpointViolations: 1},
		{TruncationDetected: true},
	}
	for _, result := range tests {
		if !auditVerifyHasProblems(result) {
			t.Fatalf("auditVerifyHasProblems(%+v) = false", result)
		}
	}
	if auditVerifyHasProblems(audit.VerifyResult{}) {
		t.Fatal("auditVerifyHasProblems(empty) = true")
	}
}

func TestAuditVerifyOutputIncludesCoreV2IntegrityState(t *testing.T) {
	result := audit.VerifyResult{
		Total:                 3,
		Valid:                 2,
		Authenticated:         2,
		LegacyUnauthenticated: 1,
		EncryptedOpaque:       4,
		IntegrityErrors:       1,
		SequenceViolations:    2,
		CheckpointViolations:  3,
		TruncationDetected:    true,
		Lock:                  audit.VerifyLockStatus{Present: true},
		Files: []audit.VerifyFileResult{{
			Path:                     "audit.log",
			Total:                    3,
			Valid:                    2,
			TimestampOrderViolations: 5,
			Authenticated:            2,
			LegacyUnauthenticated:    1,
			EncryptedOpaque:          4,
			IntegrityErrors:          1,
			SequenceViolations:       2,
			Quarantine:               "audit.quarantine.log",
		}},
	}

	for _, test := range []struct {
		name   string
		output string
		want   []string
	}{
		{
			name:   "json",
			output: "json",
			want: []string{
				`"integrityErrors": 1`,
				`"sequenceViolations": 2`,
				`"checkpointViolations": 3`,
				`"truncationDetected": true`,
			},
		},
		{
			name:   "table",
			output: "table",
			want: []string{
				"TIMESTAMP_ORDER_VIOLATIONS",
				"LEGACY_UNAUTHENTICATED",
				"ENCRYPTED_OPAQUE",
				"INTEGRITY_ERRORS",
				"SEQUENCE_VIOLATIONS",
				"QUARANTINE",
				"checkpointViolations=3",
				"truncationDetected=true",
				"lockPresent=true",
			},
		},
		{
			name:   "plain",
			output: "plain",
			want: []string{
				"authenticated=2",
				"legacyUnauthenticated=1",
				"encryptedOpaque=4",
				"checkpointViolations=3",
				"truncationDetected=true",
				"lockPresent=true",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var printErr error
			out := captureStdout(t, func() {
				printErr = printAuditVerifyResult(&cliFlags{Output: test.output}, result)
			})
			if printErr != nil {
				t.Fatalf("printAuditVerifyResult() error = %v", printErr)
			}
			for _, want := range test.want {
				if !strings.Contains(out, want) {
					t.Fatalf("output missing %q: %s", want, out)
				}
			}
		})
	}
}
