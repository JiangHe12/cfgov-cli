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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/printer"
	"github.com/JiangHe12/opskit-core/redact"
	"github.com/JiangHe12/opskit-core/safety"
	"github.com/JiangHe12/opskit-core/telemetry"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	apolloBackend "github.com/JiangHe12/cfgov-cli/internal/backend/apollo"
	etcdBackend "github.com/JiangHe12/cfgov-cli/internal/backend/etcd"
	k8sBackend "github.com/JiangHe12/cfgov-cli/internal/backend/k8s"
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
	allowProductionFlagDelete   = safety.AllowFlag("allow-production-flag-delete")
	auditStatusSkipped          = "skipped"
)

type cliFlags struct {
	Config         string
	Context        string
	Backend        string
	Server         string
	Username       string
	Password       string
	Namespace      string
	Timeout        time.Duration
	Output         string
	PlainHead      bool
	Debug          bool
	Trace          bool
	TraceBodyLim   int
	StrictNoChange bool
	AuditMaxSize   int64
	BackupKeep     int
	DryRun         bool
	Plan           bool
	Diff           bool
	Yes            bool
	Backup         bool
	NoBackup       bool
	Ticket         string
	Operator       string
	Reason         string
	NonInter       bool
	AllowDel       bool
	AllowPrune     bool
	AllowNSDel     bool
	AllowSvcDereg  bool
	AllowRuleDel   bool
	AllowFlagDel   bool
	Concurrency    int
	K8sKubeconfig  string
	K8sContext     string
	OTLPEnd        string
	OTLPMetrics    string
	OTLPInsec      bool
	contextOnce    sync.Once
	cachedCtx      string
	commandCtx     context.Context
	commandName    string
	commandTime    time.Time
	activeSpan     trace.Span
	telemetryStop  telemetry.ShutdownFunc
	metricsStop    telemetry.ShutdownFunc
	metricAttrs    []attribute.KeyValue
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
	telemetry.Configure(telemetry.Config{ServiceName: "cfgov-cli", AttributePrefix: "cfgov", MetricNamePrefix: "cfgov", DomainAttributeName: "resource"})
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
	return &cliFlags{Timeout: 30 * time.Second, Output: "table", TraceBodyLim: 2048, AuditMaxSize: audit.DefaultMaxSizeBytes, BackupKeep: 10}
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
			traceEndpoint, metricsEndpoint, insecure, ctxMeta, ctxName := resolveTelemetryConfig(f)
			f.telemetryStop = telemetry.Init(c.Context(), traceEndpoint, insecure, v)
			f.metricsStop = telemetry.InitMetrics(c.Context(), metricsEndpoint, insecure, v)
			spanCtx, span := telemetry.Tracer().Start(c.Context(), f.commandName)
			f.metricAttrs = telemetry.SpanAttributes(currentOperator(f), ctxName, ctxMeta.Env, "", f.Ticket, ctxMeta.Protected, true, "")
			span.SetAttributes(f.metricAttrs...)
			f.commandCtx = spanCtx
			f.activeSpan = span
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&f.Config, "config", "", "Override context config path")
	cmd.PersistentFlags().StringVar(&f.Context, "context", "", "Temporarily use a named context for this command")
	cmd.PersistentFlags().StringVar(&f.Backend, "backend", "", "Backend override: nacos | apollo | etcd | k8s")
	cmd.PersistentFlags().StringVar(&f.Server, "server", "", "Backend server URL")
	cmd.PersistentFlags().StringVar(&f.Username, "username", "", "Backend username")
	cmd.PersistentFlags().StringVar(&f.Password, "password", "", "Backend password")
	_ = cmd.PersistentFlags().MarkHidden("password")
	cmd.PersistentFlags().StringVarP(&f.Namespace, "namespace", "n", "", "Backend namespace")
	cmd.PersistentFlags().DurationVar(&f.Timeout, "timeout", 30*time.Second, "Request timeout")
	cmd.PersistentFlags().StringVarP(&f.Output, "output", "o", "table", "Output format: table | json | plain")
	cmd.PersistentFlags().BoolVar(&f.PlainHead, "plain-header", false, "Show headers in plain output")
	cmd.PersistentFlags().BoolVar(&f.Debug, "debug", false, "Output backend request summary to stderr")
	cmd.PersistentFlags().BoolVar(&f.Trace, "trace", false, "Output backend request/response trace to stderr")
	cmd.PersistentFlags().IntVar(&f.TraceBodyLim, "trace-body-limit", 2048, "Trace body byte limit (0 = unlimited)")
	_ = cmd.PersistentFlags().MarkHidden("trace-body-limit")
	cmd.PersistentFlags().BoolVar(&f.StrictNoChange, "strict-no-change", false, "Exit 13 (NO_CHANGE_REQUIRED) when a plan has no changes to apply")
	cmd.PersistentFlags().Int64Var(&f.AuditMaxSize, "audit-max-size", audit.DefaultMaxSizeBytes, "Active audit log rotation size in bytes")
	cmd.PersistentFlags().IntVar(&f.BackupKeep, "backup-keep", 10, "Number of local backup snapshots to keep")
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
	cmd.PersistentFlags().BoolVar(&f.AllowFlagDel, "allow-production-flag-delete", false, "Allow protected feature flag delete")
	cmd.PersistentFlags().IntVar(&f.Concurrency, "concurrency", 1, "Maximum concurrent batch operations")
	cmd.PersistentFlags().StringVar(&f.K8sKubeconfig, "k8s-kubeconfig", "", "Kubernetes kubeconfig path")
	cmd.PersistentFlags().StringVar(&f.K8sContext, "k8s-context", "", "Kubernetes kubeconfig context")
	cmd.PersistentFlags().StringVar(&f.OTLPEnd, "otel-endpoint", "", "OTLP trace endpoint")
	cmd.PersistentFlags().StringVar(&f.OTLPMetrics, "otel-metrics-endpoint", "", "OTLP metrics endpoint")
	cmd.PersistentFlags().BoolVar(&f.OTLPInsec, "otel-insecure", false, "Disable TLS for OTLP exporter")

	cmd.AddCommand(newContextCmd(f), newConfigCmd(f), newNamespaceCmd(f), newServiceCmd(f), newRuleCmd(f), newFlagCmd(f), newBackupCmd(f), newCapabilitiesCmd(f), newAuditCmd(f), newDoctorCmd(f), newCompletionCmd(f), newVersionCmd(f), newInstallCmd(f))
	setSuggestionsRecursive(cmd, 1)
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
	if f.activeSpan != nil {
		if err != nil {
			f.activeSpan.RecordError(err)
			f.activeSpan.SetStatus(codes.Error, err.Error())
		} else {
			f.activeSpan.SetStatus(codes.Ok, "")
		}
		f.activeSpan.End()
	}
	if !f.commandTime.IsZero() {
		status := "success"
		if err != nil {
			status = "error"
		}
		telemetry.RecordCommand(ctx, f.commandName, status, time.Since(f.commandTime), f.metricAttrs)
	}
	if f.telemetryStop != nil || f.metricsStop != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if f.telemetryStop != nil {
			f.telemetryStop(shutdownCtx)
		}
		if f.metricsStop != nil {
			f.metricsStop(shutdownCtx)
		}
		cancel()
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

func resolveTelemetryConfig(f *cliFlags) (traceEndpoint, metricsEndpoint string, insecure bool, ctxMeta cfgovctx.Context, ctxName string) {
	ctxMeta, ctxName, _ = resolvedContext(f)
	traceEndpoint = firstNonEmpty(f.OTLPEnd, ctxMeta.OTLPEndpoint, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	metricsEndpoint = firstNonEmpty(f.OTLPMetrics, ctxMeta.OTLPMetricsEndpoint, os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"))
	insecure = f.OTLPInsec || ctxMeta.OTLPInsecure
	if ctxName == "" {
		ctxName = f.contextName()
	}
	return traceEndpoint, metricsEndpoint, insecure, ctxMeta, ctxName
}

func setSuggestionsRecursive(cmd *cobra.Command, distance int) {
	cmd.SuggestionsMinimumDistance = distance
	for _, child := range cmd.Commands() {
		setSuggestionsRecursive(child, distance)
	}
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
	if backendName == "apollo" {
		if err := validateServerURL(server); err != nil {
			return nil, cfgovctx.Context{}, err
		}
		backend, err := buildApolloBackend(f, name, item, server)
		return backend, item, err
	}
	if backendName == "etcd" {
		backend, err := buildEtcdBackend(f, name, item, server)
		return backend, item, err
	}
	if backendName == "k8s" {
		backend, err := buildK8sBackend(f, item)
		return backend, item, err
	}
	if backendName != "nacos" {
		return nil, cfgovctx.Context{}, apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
	}
	if err := validateServerURL(server); err != nil {
		return nil, cfgovctx.Context{}, err
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
	client.SetTrace(api.TraceOptions{Debug: f.Debug, Trace: f.Trace, BodyLimit: f.TraceBodyLim, Writer: os.Stderr})
	return nacosbackend.New(client, server), item, nil
}

func backendServerEnv(backendName string) string {
	switch backendName {
	case "apollo":
		return os.Getenv("APOLLO_SERVER")
	case "etcd":
		return firstNonEmpty(os.Getenv("ETCD_ENDPOINTS"), os.Getenv("ETCD_SERVER"))
	case "k8s":
		return ""
	default:
		return os.Getenv("NACOS_SERVER")
	}
}

func buildK8sBackend(f *cliFlags, item cfgovctx.Context) (cfgov.Backend, error) {
	backend, err := k8sBackend.New(k8sBackend.Options{
		Kubeconfig: firstNonEmpty(f.K8sKubeconfig, item.K8sKubeconfig, os.Getenv("KUBECONFIG")),
		Context:    firstNonEmpty(f.K8sContext, item.K8sContext),
		Namespace:  firstNonEmpty(f.Namespace, item.Namespace),
		Timeout:    f.Timeout,
		Trace:      f.Debug || f.Trace,
		TraceOut:   os.Stderr,
	})
	if err != nil {
		return nil, err
	}
	return backend, nil
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
		Trace:         f.Debug || f.Trace,
		TraceOut:      os.Stderr,
	})
	if err != nil {
		return nil, err
	}
	return backend, nil
}

func buildEtcdBackend(f *cliFlags, contextName string, item cfgovctx.Context, server string) (cfgov.Backend, error) {
	password := firstNonEmpty(f.Password, os.Getenv("ETCD_PASSWORD"))
	if password == "" {
		resolved, err := cfgovctx.ResolvePassword(commandContext(f), contextName, item)
		if err != nil {
			return nil, err
		}
		password = resolved
	}
	backend, err := etcdBackend.New(etcdBackend.Options{
		Endpoints:     server,
		KeyPrefix:     firstNonEmpty(os.Getenv("ETCD_KEY_PREFIX"), item.EtcdKeyPrefix),
		Namespace:     firstNonEmpty(f.Namespace, os.Getenv("ETCD_NAMESPACE"), item.Namespace),
		RuleNamespace: firstNonEmpty(os.Getenv("ETCD_RULE_NAMESPACE"), item.EtcdRuleNamespace),
		Username:      firstNonEmpty(f.Username, os.Getenv("ETCD_USERNAME"), item.Username),
		Password:      password,
		CACert:        firstNonEmpty(os.Getenv("ETCD_CACERT"), item.EtcdCACert),
		ClientCert:    firstNonEmpty(os.Getenv("ETCD_CLIENT_CERT"), item.EtcdClientCert),
		ClientKey:     firstNonEmpty(os.Getenv("ETCD_CLIENT_KEY"), item.EtcdClientKey),
		Timeout:       f.Timeout,
		Trace:         f.Debug || f.Trace,
		TraceOut:      os.Stderr,
	})
	if err != nil {
		return nil, err
	}
	return backend, nil
}

func resolvedContext(f *cliFlags) (cfgovctx.Context, string, error) {
	if f.Context != "" {
		cfg, err := cfgovctx.Load()
		if err != nil {
			return cfgovctx.Context{}, "", err
		}
		item, ok := cfg.Contexts[f.Context]
		if !ok {
			return cfgovctx.Context{}, "", apperrors.New(apperrors.CodeUsageError, "context not found", nil)
		}
		return item, f.Context, nil
	}
	ctx, name, err := cfgovctx.Current()
	if err != nil {
		backendName := firstNonEmpty(f.Backend, "nacos")
		if backendName != "k8s" && f.Server == "" && backendServerEnv(backendName) == "" {
			return cfgovctx.Context{}, "", err
		}
		return cfgovctx.Context{Backend: backendName, Namespace: f.Namespace}, "direct", nil
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
			allowProductionFlagDelete:   f.AllowFlagDel,
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

func isStrictNoChange(f *cliFlags) bool {
	return f.StrictNoChange
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
	if appendErr := audit.AppendWithOptions(path, evt, auditOptions(f)); appendErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: audit write failed: %v\n", appendErr)
	}
}

func auditOptions(f *cliFlags) audit.Options {
	maxSize := f.AuditMaxSize
	if maxSize <= 0 {
		maxSize = audit.DefaultMaxSizeBytes
	}
	return audit.Options{MaxSizeBytes: maxSize}
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
	if f.Context != "" {
		return f.Context
	}
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
