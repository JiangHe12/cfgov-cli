package cmd

import (
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

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
