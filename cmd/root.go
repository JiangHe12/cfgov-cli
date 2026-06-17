package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	osuser "os/user"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/printer"
	"github.com/JiangHe12/opskit-core/redact"
	"github.com/JiangHe12/opskit-core/safety"
	"github.com/JiangHe12/opskit-core/telemetry"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	apolloBackend "github.com/JiangHe12/cfgov-cli/internal/backend/apollo"
	nacosbackend "github.com/JiangHe12/cfgov-cli/internal/backend/nacos"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

const (
	apiVersion                  = "cfgov-cli.io/v1"
	auditAPIVersion             = "cfgov-cli.io/audit/v1"
	allowProductionConfigDelete = safety.AllowFlag("allow-production-config-delete")
	allowProductionPrune        = safety.AllowFlag("allow-production-prune")
	allowProductionNamespaceDel = safety.AllowFlag("allow-production-namespace-delete")
	allowProductionServiceDereg = safety.AllowFlag("allow-production-service-deregister")
	allowProductionRuleDelete   = safety.AllowFlag("allow-production-rule-delete")
)

type cliFlags struct {
	Config        string
	Backend       string
	Server        string
	Username      string
	Password      string
	Namespace     string
	Timeout       time.Duration
	Output        string
	PlainHead     bool
	DryRun        bool
	Plan          bool
	Diff          bool
	Yes           bool
	Backup        bool
	NoBackup      bool
	Ticket        string
	Operator      string
	Reason        string
	NonInter      bool
	AllowDel      bool
	AllowPrune    bool
	AllowNSDel    bool
	AllowSvcDereg bool
	AllowRuleDel  bool
	Concurrency   int
	OTLPEnd       string
	OTLPMetrics   string
	OTLPInsec     bool
	contextOnce   sync.Once
	cachedCtx     string
	commandCtx    context.Context
	commandName   string
	commandTime   time.Time
}

var versionInfo = struct {
	sync.RWMutex
	version string
	commit  string
	built   string
}{version: "dev", commit: "unknown", built: "unknown"}

func init() {
	cfgovctx.Configure()
	apperrors.Configure(apperrors.Options{APIVersion: apiVersion})
	printer.Configure(printer.Options{APIVersion: apiVersion, JSONEnvelopeByDefault: true})
	audit.Configure(audit.Config{APIVersion: auditAPIVersion, ConfigDirName: ".cfgov-cli", PrivateKeyEnvVar: "CFGOV_CLI_AUDIT_PRIVATE_KEY"})
	safety.Configure(safety.Config{Prompt: "Proceed with cfgov write? [y/N] ", OperatorEnvVar: "CFGOV_CLI_OPERATOR"})
}

func SetVersionInfo(version, commit, built string) {
	versionInfo.Lock()
	defer versionInfo.Unlock()
	versionInfo.version = version
	versionInfo.commit = commit
	versionInfo.built = built
}

func getVersionInfo() (string, string, string) {
	versionInfo.RLock()
	defer versionInfo.RUnlock()
	return versionInfo.version, versionInfo.commit, versionInfo.built
}

func newDefaultFlags() *cliFlags {
	return &cliFlags{Timeout: 30 * time.Second, Output: "table"}
}

func NewRootCmd() *cobra.Command {
	return newRootCmdWith(newDefaultFlags())
}

func newRootCmdWith(f *cliFlags) *cobra.Command {
	v, _, _ := getVersionInfo()
	cmd := &cobra.Command{
		Use:           "cfgov",
		Short:         "Governed configuration CLI",
		Version:       v,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			f.commandCtx = c.Context()
			f.commandName = strings.ReplaceAll(c.CommandPath(), " ", ".")
			f.commandTime = time.Now()
			if f.Config != "" {
				cfgovctx.SetConfigPath(f.Config)
			}
			if err := validateOutput(f.Output); err != nil {
				return err
			}
			if f.Concurrency <= 0 || f.Concurrency > 16 {
				return apperrors.New(apperrors.CodeUsageError, "--concurrency must be between 1 and 16", nil)
			}
			telemetry.Init(c.Context(), f.OTLPEnd, f.OTLPInsec, v)
			telemetry.InitMetrics(c.Context(), f.OTLPMetrics, f.OTLPInsec, v)
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&f.Config, "config", "", "Override context config path")
	cmd.PersistentFlags().StringVar(&f.Backend, "backend", "", "Backend override: nacos | apollo")
	cmd.PersistentFlags().StringVar(&f.Server, "server", "", "Backend server URL")
	cmd.PersistentFlags().StringVar(&f.Username, "username", "", "Backend username")
	cmd.PersistentFlags().StringVar(&f.Password, "password", "", "Backend password")
	_ = cmd.PersistentFlags().MarkHidden("password")
	cmd.PersistentFlags().StringVarP(&f.Namespace, "namespace", "n", "", "Backend namespace")
	cmd.PersistentFlags().DurationVar(&f.Timeout, "timeout", 30*time.Second, "Request timeout")
	cmd.PersistentFlags().StringVarP(&f.Output, "output", "o", "table", "Output format: table | json | plain")
	cmd.PersistentFlags().BoolVar(&f.PlainHead, "plain-header", false, "Show headers in plain output")
	cmd.PersistentFlags().BoolVar(&f.DryRun, "dry-run", false, "Plan only, do not mutate")
	cmd.PersistentFlags().BoolVar(&f.Plan, "plan", false, "Alias for --dry-run plan output")
	cmd.PersistentFlags().BoolVar(&f.Diff, "diff", false, "Include CLI-computed impact summary")
	cmd.PersistentFlags().BoolVar(&f.Yes, "yes", false, "Confirm write authorization")
	cmd.PersistentFlags().BoolVar(&f.Backup, "backup", false, "Backup current remote config before writing")
	cmd.PersistentFlags().BoolVar(&f.NoBackup, "no-backup", false, "Explicitly skip backup before writing")
	cmd.PersistentFlags().StringVar(&f.Ticket, "ticket", "", "Human-supplied change ticket")
	cmd.PersistentFlags().StringVar(&f.Operator, "operator", "", "Operator identity")
	cmd.PersistentFlags().StringVar(&f.Reason, "reason", "", "Change reason")
	cmd.PersistentFlags().BoolVar(&f.NonInter, "non-interactive", false, "Disable interactive confirmation")
	cmd.PersistentFlags().BoolVar(&f.AllowDel, "allow-production-config-delete", false, "Allow protected config delete")
	cmd.PersistentFlags().BoolVar(&f.AllowPrune, "allow-production-prune", false, "Allow protected reconcile prune actions")
	cmd.PersistentFlags().BoolVar(&f.AllowNSDel, "allow-production-namespace-delete", false, "Allow protected namespace delete")
	cmd.PersistentFlags().BoolVar(&f.AllowSvcDereg, "allow-production-service-deregister", false, "Allow protected service deregister")
	cmd.PersistentFlags().BoolVar(&f.AllowRuleDel, "allow-production-rule-delete", false, "Allow protected Sentinel rule delete")
	cmd.PersistentFlags().IntVar(&f.Concurrency, "concurrency", 1, "Maximum concurrent batch operations")
	cmd.PersistentFlags().StringVar(&f.OTLPEnd, "otel-endpoint", "", "OTLP trace endpoint")
	cmd.PersistentFlags().StringVar(&f.OTLPMetrics, "otel-metrics-endpoint", "", "OTLP metrics endpoint")
	cmd.PersistentFlags().BoolVar(&f.OTLPInsec, "otel-insecure", false, "Disable TLS for OTLP exporter")

	cmd.AddCommand(newContextCmd(f), newConfigCmd(f), newNamespaceCmd(f), newServiceCmd(f), newRuleCmd(f), newCapabilitiesCmd(f), newAuditCmd(f), newVersionCmd(f), newInstallCmd(f))
	return cmd
}

func Execute() {
	if os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(os.Stdout.Fd()) {
		color.NoColor = true
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	f := newDefaultFlags()
	cmd := newRootCmdWith(f)
	err := cmd.ExecuteContext(ctx)
	if !f.commandTime.IsZero() {
		status := "success"
		if err != nil {
			status = "error"
		}
		telemetry.RecordCommand(ctx, f.commandName, status, time.Since(f.commandTime), nil)
	}
	if err == nil || errors.Is(err, context.Canceled) {
		stop()
		return
	}
	code := apperrors.ExitCode(err)
	if outputFlagFromArgs(os.Args[1:]) == "json" {
		_ = apperrors.WriteJSON(os.Stderr, err)
	} else {
		appErr := apperrors.AsAppError(err)
		_, _ = fmt.Fprintf(os.Stderr, "x %s\n", appErr.Error())
		if appErr.Suggestion != "" {
			_, _ = fmt.Fprintf(os.Stderr, "\nSuggestion:\n  %s\n", appErr.Suggestion)
		}
	}
	stop()
	os.Exit(code)
}

func buildBackend(f *cliFlags) (cfgov.Backend, cfgovctx.Context, error) {
	item, name, err := resolvedContext(f)
	if err != nil {
		return nil, cfgovctx.Context{}, err
	}
	backendName := firstNonEmpty(f.Backend, item.Backend)
	if backendName == "" {
		backendName = "nacos"
	}
	server := firstNonEmpty(f.Server, backendServerEnv(backendName), item.Server)
	if err := validateServerURL(server); err != nil {
		return nil, cfgovctx.Context{}, err
	}
	if backendName == "apollo" {
		backend, err := buildApolloBackend(f, name, item, server)
		return backend, item, err
	}
	if backendName != "nacos" {
		return nil, cfgovctx.Context{}, apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
	}
	username := firstNonEmpty(f.Username, os.Getenv("NACOS_USERNAME"), item.Username)
	password := firstNonEmpty(f.Password, os.Getenv("NACOS_PASSWORD"))
	if password == "" {
		resolved, rerr := cfgovctx.ResolvePassword(commandContext(f), name, item)
		if rerr != nil {
			return nil, cfgovctx.Context{}, rerr
		}
		password = resolved
	}
	namespace := firstNonEmpty(f.Namespace, os.Getenv("NACOS_NAMESPACE"), item.Namespace)
	client := api.NewClient(server, username, password, namespace, f.Timeout)
	return nacosbackend.New(client, server), item, nil
}

func backendServerEnv(backendName string) string {
	if backendName == "apollo" {
		return os.Getenv("APOLLO_SERVER")
	}
	return os.Getenv("NACOS_SERVER")
}

func buildApolloBackend(f *cliFlags, contextName string, item cfgovctx.Context, server string) (cfgov.Backend, error) {
	token := firstNonEmpty(f.Password, os.Getenv("APOLLO_TOKEN"), os.Getenv("APOLLO_SECRET"))
	if token == "" {
		resolved, err := cfgovctx.ResolvePassword(commandContext(f), contextName, item)
		if err != nil {
			return nil, err
		}
		token = resolved
	}
	backend, err := apolloBackend.New(apolloBackend.Options{
		Server:        server,
		Token:         token,
		AppID:         firstNonEmpty(os.Getenv("APOLLO_APP_ID"), item.ApolloAppID, item.Username),
		Env:           firstNonEmpty(os.Getenv("APOLLO_ENV"), item.ApolloEnv),
		Cluster:       firstNonEmpty(os.Getenv("APOLLO_CLUSTER"), item.ApolloCluster),
		Namespace:     firstNonEmpty(f.Namespace, os.Getenv("APOLLO_NAMESPACE"), item.ApolloNamespace, item.Namespace),
		RuleNamespace: firstNonEmpty(os.Getenv("APOLLO_RULE_NAMESPACE"), item.ApolloRuleNamespace),
		Operator:      currentOperator(f),
		Reason:        f.Reason,
		Timeout:       f.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return backend, nil
}

func resolvedContext(f *cliFlags) (cfgovctx.Context, string, error) {
	ctx, name, err := cfgovctx.Current()
	if err != nil {
		if f.Server == "" && os.Getenv("NACOS_SERVER") == "" {
			return cfgovctx.Context{}, "", err
		}
		return cfgovctx.Context{Backend: "nacos", Namespace: f.Namespace}, "direct", nil
	}
	return *ctx, name, nil
}

func authorize(f *cliFlags, base safety.Risk, meta cfgovctx.Context, required safety.AllowFlag) error {
	risk := safety.EffectiveRisk(base, safety.ContextMeta{
		Env:             meta.Env,
		Protected:       meta.Protected,
		TicketPattern:   meta.TicketPattern,
		TicketValidator: meta.TicketValidator,
		Roles:           meta.Roles,
	})
	err := safety.Authorize(risk, safety.Options{
		Yes:                f.Yes,
		NonInteractive:     f.NonInter,
		Ticket:             f.Ticket,
		TicketPattern:      meta.TicketPattern,
		Validator:          ticketValidator(meta.TicketValidator, f.contextName(), currentOperator(f)),
		RequiredAllowFlags: requiredAllow(required),
		GrantedAllowFlags: map[safety.AllowFlag]bool{
			allowProductionConfigDelete: f.AllowDel,
			allowProductionPrune:        f.AllowPrune,
			allowProductionNamespaceDel: f.AllowNSDel,
			allowProductionServiceDereg: f.AllowSvcDereg,
			allowProductionRuleDelete:   f.AllowRuleDel,
		},
		Roles:    meta.Roles,
		Operator: currentOperator(f),
	})
	if err != nil {
		telemetry.RecordAuthorizationDenied(commandContext(f), "authorization", nil)
		appendAuditWarn(f, audit.EventAuthorizationDenied, meta, audit.EventTarget{ResourceType: "config"}, audit.StatusDenied, "", err)
	}
	return err
}

func ticketValidator(path, contextName, operator string) safety.TicketValidator {
	if path == "" {
		return nil
	}
	return safety.NewExternalValidator(path, contextName, operator)
}

func requiredAllow(flag safety.AllowFlag) []safety.AllowFlag {
	if flag == "" {
		return nil
	}
	return []safety.AllowFlag{flag}
}

func appendAuditWarn(f *cliFlags, typ audit.EventType, ctx cfgovctx.Context, target audit.EventTarget, status, diff string, err error) {
	path, pathErr := audit.DefaultPath()
	if pathErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: audit path failed: %v\n", pathErr)
		return
	}
	evt := audit.Event{
		EventType: typ,
		Operator:  currentOperator(f),
		Context:   audit.EventContext{Name: f.contextName(), Env: ctx.Env, Protected: ctx.Protected},
		Ticket:    f.Ticket,
		Reason:    f.Reason,
		Target:    target,
		Status:    status,
		Diff:      redact.String(diff),
	}
	if err != nil {
		appErr := apperrors.AsAppError(err)
		evt.Error = &audit.EventError{Code: string(appErr.Code), Message: appErr.Message}
	}
	if appendErr := audit.Append(path, evt); appendErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: audit write failed: %v\n", appendErr)
	}
}

func newPrinter(f *cliFlags) *printer.Printer {
	p := printer.New(printer.FormatTable)
	switch f.Output {
	case "json":
		p = printer.New(printer.FormatJSON)
	case "plain":
		p = printer.New(printer.FormatPlain)
	}
	p.PlainHead = f.PlainHead
	return p
}

func commandContext(f *cliFlags) context.Context {
	if f.commandCtx != nil {
		return f.commandCtx
	}
	return context.Background()
}

func (f *cliFlags) contextName() string {
	f.contextOnce.Do(func() {
		_, name, err := cfgovctx.Current()
		if err != nil || name == "" {
			name = "direct"
		}
		f.cachedCtx = name
	})
	return f.cachedCtx
}

func currentOperator(f *cliFlags) string {
	if f.Operator != "" {
		return f.Operator
	}
	if env := os.Getenv("CFGOV_CLI_OPERATOR"); env != "" {
		return env
	}
	if u, err := osuser.Current(); err == nil && u != nil && u.Username != "" {
		if host, herr := os.Hostname(); herr == nil && host != "" {
			return u.Username + "@" + host
		}
		return u.Username
	}
	return "unknown"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func validateOutput(output string) error {
	switch output {
	case "", "table", "json", "plain":
		return nil
	default:
		return apperrors.New(apperrors.CodeUsageError, "output format must be table, json, or plain", nil)
	}
}

func validateServerURL(server string) error {
	if server == "" {
		return apperrors.New(apperrors.CodeUsageError, "nacos server address not specified", nil)
	}
	parsed, err := url.Parse(server)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return apperrors.New(apperrors.CodeUsageError, "invalid Nacos server URL", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return apperrors.New(apperrors.CodeUsageError, "Nacos server URL must use http or https", nil)
	}
	return nil
}

func outputFlagFromArgs(args []string) string {
	for i, arg := range args {
		if (arg == "-o" || arg == "--output") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "--output=") {
			return strings.TrimPrefix(arg, "--output=")
		}
		if strings.HasPrefix(arg, "-o=") {
			return strings.TrimPrefix(arg, "-o=")
		}
	}
	return ""
}
