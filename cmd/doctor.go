package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/redact"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type doctorResult struct {
	Checks   []doctorCheck `json:"checks"`
	OK       bool          `json:"ok"`
	Complete bool          `json:"complete"`
	DryRun   bool          `json:"dryRun,omitempty"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Backend string `json:"backend,omitempty"`
	Context string `json:"context,omitempty"`
	Latency string `json:"latency,omitempty"`
}

type doctorBackendReadResult struct {
	Auth    doctorCheck
	Backend doctorCheck
}

func newDoctorCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run read-only diagnostics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.Context(), f)
		},
	}
}

func runDoctor(ctx context.Context, f *cliFlags) error {
	planOnly := isPlanOnly(f)
	result := doctorResult{OK: true, Complete: true, DryRun: planOnly}
	ctxMeta, ctxName, ctxErr := resolvedContext(f)
	if ctxErr != nil {
		result.add(doctorFailed("context", ctxErr))
	} else {
		result.add(doctorCheck{Name: "context", Status: audit.StatusSuccess, Context: ctxName, Message: redact.String("context loaded")})
		result.add(doctorWriteProbeCheck(ctxMeta, ctxName))
	}

	if ctxErr != nil {
		result.add(doctorFailed("backend", ctxErr))
	} else {
		checks, err := doctorBackendChecks(ctx, f, ctxMeta, ctxName)
		if err != nil {
			return err
		}
		for _, check := range checks {
			result.add(check)
		}
	}

	if planOnly {
		markPreview(f)
		result.add(doctorAuditPlanCheck(f))
	} else {
		result.add(doctorAuditCheck(f))
		appendAuditWarn(f, audit.EventType("doctor"), ctxMeta, audit.EventTarget{ResourceType: "diagnostic"}, audit.StatusSuccess, "doctor checks="+intString(len(result.Checks)), nil)
	}
	if err := printDoctorResult(f, result); err != nil {
		return err
	}
	if !result.OK {
		return apperrors.New(apperrors.CodeValidationFailed, "doctor checks failed", nil)
	}
	return nil
}

func doctorBackendChecks(ctx context.Context, f *cliFlags, ctxMeta cfgovctx.Context, ctxName string) ([]doctorCheck, error) {
	spec := newReadAuditSpec(
		"doctor.ping",
		ctxMeta,
		"diagnostic",
		ctxName+"\x00"+firstNonEmpty(ctxMeta.Backend, f.Backend, "nacos"),
		map[string]string{"context": ctxName},
	)
	spec.ContextName = ctxName
	readResult, operationErr, auditErr := executeMandatoryRead(
		f,
		spec,
		func() (doctorBackendReadResult, error) {
			authCheck, authErr := doctorAuthCheck(f, ctxMeta, ctxName)
			backend, _, buildErr := buildBackendForResolvedContext(f, ctxMeta, ctxName)
			if buildErr != nil {
				return doctorBackendReadResult{
					Auth:    authCheck,
					Backend: doctorFailed("backend", buildErr),
				}, errors.Join(authErr, buildErr)
			}
			start := time.Now()
			pingErr := backend.Ping(ctx)
			return doctorBackendReadResult{
				Auth: authCheck,
				Backend: doctorCheck{
					Name:    "backend",
					Status:  auditStatus(pingErr),
					Message: doctorMessage("ping ok", pingErr),
					Backend: backend.Describe().Backend,
					Context: ctxName,
					Latency: time.Since(start).String(),
				},
			}, errors.Join(authErr, pingErr)
		},
		func(doctorBackendReadResult) int { return 2 },
	)
	if auditErr != nil {
		return nil, auditErr
	}
	if operationErr != nil && readResult.Auth.Name == "" && readResult.Backend.Name == "" {
		return nil, operationErr
	}
	checks := make([]doctorCheck, 0, 2)
	if readResult.Auth.Name != "" {
		checks = append(checks, readResult.Auth)
	}
	if readResult.Backend.Name != "" {
		checks = append(checks, readResult.Backend)
	}
	return checks, nil
}

func (r *doctorResult) add(check doctorCheck) {
	if check.Status == audit.StatusFailed {
		r.OK = false
	}
	if check.Status == auditStatusSkipped {
		r.Complete = false
	}
	r.Checks = append(r.Checks, check)
}

func doctorAuthCheck(f *cliFlags, meta cfgovctx.Context, ctxName string) (doctorCheck, error) {
	if _, err := cfgovctx.ResolvePassword(commandContext(f), ctxName, meta); err != nil {
		return doctorFailed("auth", err), err
	}
	return doctorCheck{Name: "auth", Status: audit.StatusSuccess, Message: redact.String("credentials resolvable"), Context: ctxName}, nil
}

func doctorWriteProbeCheck(meta cfgovctx.Context, ctxName string) doctorCheck {
	effective := safety.EffectiveRisk(safety.R1, safety.ContextMeta{
		Env:             meta.Env,
		Protected:       meta.Protected,
		TicketPattern:   meta.TicketPattern,
		TicketValidator: meta.TicketValidator,
		Roles:           meta.Roles,
	})
	return doctorCheck{
		Name:    "write-probe",
		Status:  audit.StatusSuccess,
		Message: redact.String(fmt.Sprintf("write governance path reachable; effectiveRisk=%v; backend mutation not attempted", effective)),
		Context: ctxName,
	}
}

func doctorAuditCheck(f *cliFlags) doctorCheck {
	path, err := audit.DefaultPath()
	if err != nil {
		return doctorFailed("audit", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return doctorFailed("audit", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // audit.DefaultPath returns the governed local audit log path.
	if err != nil {
		return doctorFailed("audit", err)
	}
	if err := file.Close(); err != nil {
		return doctorFailed("audit", err)
	}
	return doctorCheck{Name: "audit", Status: audit.StatusSuccess, Message: redact.String("audit log writable"), Context: f.contextName()}
}

func doctorAuditPlanCheck(f *cliFlags) doctorCheck {
	path, err := audit.DefaultPath()
	if err != nil {
		return doctorFailed("audit", err)
	}
	return doctorCheck{
		Name:    "audit",
		Status:  auditStatusSkipped,
		Message: redact.String("audit write check skipped in plan; writability not verified; path=" + path),
		Context: f.contextName(),
	}
}

func doctorFailed(name string, err error) doctorCheck {
	return doctorCheck{Name: name, Status: audit.StatusFailed, Message: redact.String(err.Error())}
}

func doctorMessage(ok string, err error) string {
	if err != nil {
		return redact.String(err.Error())
	}
	return redact.String(ok)
}

func printDoctorResult(f *cliFlags, result doctorResult) error {
	p := newPrinter(f)
	if f.Output == "json" || f.Output == "plain" {
		return p.JSONData("DoctorResult", result)
	}
	rows := make([][]string, 0, len(result.Checks))
	for _, check := range result.Checks {
		rows = append(rows, []string{check.Name, check.Status, check.Backend, check.Context, check.Latency, check.Message})
	}
	if err := p.Table([]string{"CHECK", "STATUS", "BACKEND", "CONTEXT", "LATENCY", "MESSAGE"}, rows); err != nil {
		return err
	}
	if !result.OK {
		return p.Info(fmt.Sprintf("%d checks ran; failures present", len(result.Checks)))
	} else if !result.Complete {
		return p.Info(fmt.Sprintf("%d checks ran; audit writability was not verified", len(result.Checks)))
	}
	return nil
}
