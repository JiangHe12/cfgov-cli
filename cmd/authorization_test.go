package cmd

import (
	"errors"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestAuthorizeDeleteRequiresTicket(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.Yes = true
	err := authorize(f, safety.R2, cfgovctx.Context{Backend: "nacos"}, allowProductionConfigDelete)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}
}

func TestAuthorizeProtectedDeleteRequiresAllowFlag(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"
	meta := cfgovctx.Context{Backend: "nacos", Namespace: "prod"}
	meta.Protected = true
	err := authorize(f, safety.R2, meta, allowProductionConfigDelete)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}
}

func TestAuthorizeProtectedDeletePassesWithSpecificAllowFlag(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"
	f.AllowDel = true
	meta := cfgovctx.Context{Backend: "nacos"}
	meta.Protected = true
	if err := authorize(f, safety.R2, meta, allowProductionConfigDelete); err != nil {
		t.Fatalf("authorize() error = %v", err)
	}
}

func TestTrustedOperatorIgnoresCompatibilityInputsForAuthorizationAndAudit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(cfgovOperatorEnv, "env-spoof")
	t.Setenv(deprecatedCfgovOperatorEnv, "deprecated-env-spoof")

	f := newDefaultFlags()
	f.Operator = "flag-spoof"
	f.resolveOperator = func() (string, error) { return "trusted-user@trusted-host", nil }
	operator, err := trustedOperator(f)
	if err != nil {
		t.Fatal(err)
	}
	if operator != "trusted-user@trusted-host" {
		t.Fatalf("operator = %q, want trusted OS identity", operator)
	}

	f.Yes = true
	f.Ticket = "TEST-1"
	f.AllowCtxChange = true
	meta := cfgovctx.Context{}
	meta.Roles = map[string]string{
		"flag-spoof":                safety.RoleAdmin,
		"env-spoof":                 safety.RoleAdmin,
		"deprecated-env-spoof":      safety.RoleAdmin,
		"trusted-user@trusted-host": safety.RoleReader,
	}
	err = authorizeForContext(f, safety.R3, meta, allowContextChange, "prod")
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("spoofed authorization error = %v, want authorization required", err)
	}

	appendAuditWarn(
		f,
		audit.EventType("identity.test"),
		cfgovctx.Context{},
		audit.EventTarget{ResourceType: "context", Resource: "prod"},
		audit.StatusSuccess,
		"",
		nil,
	)
	path, err := audit.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	result, err := audit.Query(path, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Fatal("audit events are empty")
	}
	for _, event := range result.Events {
		if event.Operator != "trusted-user@trusted-host" {
			t.Fatalf("audit event operator = %q, want trusted operator: %#v", event.Operator, event)
		}
	}
}

func TestTrustedOperatorResolutionFailureIsFailClosed(t *testing.T) {
	f := newDefaultFlags()
	f.resolveOperator = func() (string, error) { return "", errors.New("identity lookup failed") }
	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{"capabilities"})
	err := cmd.Execute()
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error = %v, want authorization required", err)
	}
}

func TestContextControlAuthorizationRequiresExactAllowFlag(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.resolveOperator = func() (string, error) { return "admin@host", nil }
	f.Yes = true
	f.Ticket = "TEST-1"
	f.AllowDel = true
	meta := cfgovctx.Context{}
	meta.Roles = map[string]string{"admin@host": safety.RoleAdmin}

	err := authorizeForContext(f, safety.R3, meta, allowContextDelete, "prod")
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("wrong allow flag error = %v, want authorization required", err)
	}
	f.AllowCtxDelete = true
	if err := authorizeForContext(f, safety.R3, meta, allowContextDelete, "prod"); err != nil {
		t.Fatalf("exact allow flag error = %v", err)
	}
}
