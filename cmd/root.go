package cmd

import (
	"context"
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

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/printer"
	"github.com/JiangHe12/opskit-core/v2/redact"
	"github.com/JiangHe12/opskit-core/v2/safety"
	"github.com/JiangHe12/opskit-core/v2/telemetry"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	apolloBackend "github.com/JiangHe12/cfgov-cli/internal/backend/apollo"
	consulBackend "github.com/JiangHe12/cfgov-cli/internal/backend/consul"
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
	allowProductionReconcile    = safety.AllowFlag("allow-production-reconcile")
	allowProductionPrune        = safety.AllowFlag("allow-production-prune")
	allowProductionNamespaceDel = safety.AllowFlag("allow-production-namespace-delete")
	allowProductionServiceDereg = safety.AllowFlag("allow-production-service-deregister")
	allowProductionRuleDelete   = safety.AllowFlag("allow-production-rule-delete")
	allowProductionFlagDelete   = safety.AllowFlag("allow-production-flag-delete")
	allowContextChange          = safety.AllowFlag("allow-context-change")
	allowContextDelete          = safety.AllowFlag("allow-context-delete")
	allowRoleChange             = safety.AllowFlag("allow-role-change")
	allowAuditPrune             = safety.AllowFlag("allow-audit-prune")
	allowAuditRepair            = safety.AllowFlag("allow-audit-repair")
	auditStatusSkipped          = "skipped"
)

type cliFlags struct {
	Config              string
	Context             string
	Backend             string
	Server              string
	Username            string
	Password            string
	Namespace           string
	Timeout             time.Duration
	Output              string
	PlainHead           bool
	Debug               bool
	Trace               bool
	NoColor             bool
	TraceBodyLim        int
	StrictNoChange      bool
	AuditMaxSize        int64
	DryRun              bool
	Plan                bool
	Diff                bool
	Yes                 bool
	Backup              bool
	NoBackup            bool
	Ticket              string
	Operator            string
	Reason              string
	NonInter            bool
	AllowDel            bool
	AllowReconcile      bool
	AllowPrune          bool
	AllowNSDel          bool
	AllowSvcDereg       bool
	AllowRuleDel        bool
	AllowFlagDel        bool
	AllowCtxChange      bool
	AllowCtxDelete      bool
	AllowRoleChange     bool
	AllowAuditPrune     bool
	AllowAuditRepair    bool
	K8sKubeconfig       string
	K8sContext          string
	OTLPEnd             string
	OTLPMetrics         string
	OTLPInsec           bool
	contextOnce         sync.Once
	cachedCtx           string
	commandCtx          context.Context
	commandName         string
	commandTime         time.Time
	activeSpan          trace.Span
	telemetryStop       telemetry.ShutdownFunc
	metricsStop         telemetry.ShutdownFunc
	metricAttrs         []attribute.KeyValue
	preview             bool
	trustedOperator     string
	resolveOperator     func() (string, error)
	beforeContextUpdate func()
	mutationAudit       *mutationAuditRuntime
	mutationAuditPath   string
	contextImport       *contextImportRuntime
}

var versionInfo = struct {
	sync.RWMutex
	version string
	commit  string
	built   string
}{version: "dev", commit: "unknown", built: "unknown"}

func init() {
	cfgovctx.Configure()
	errorCodes := append(apperrors.AllCodes(), codeAuditIncomplete)
	apperrors.Configure(apperrors.Options{
		APIVersion:  apiVersion,
		Codes:       errorCodes,
		Suggestions: map[apperrors.ErrorCode]string{codeAuditIncomplete: "Resolve audit storage and replay durable mutation outcomes before retrying."},
	})
	printer.Configure(printer.Options{APIVersion: apiVersion, JSONEnvelopeByDefault: true})
	audit.Configure(audit.Config{
		APIVersion:       auditAPIVersion,
		ConfigDirName:    ".cfgov-cli",
		PrivateKeyEnvVar: configureEnvWithDeprecatedAlias(cfgovAuditPrivateKeyEnv, deprecatedCfgovAuditPrivateKeyEnv),
	})
	safety.Configure(safety.Config{
		Prompt: "Proceed with cfgov write? [y/N] ",
	})
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
	return &cliFlags{
		Timeout:         30 * time.Second,
		Output:          "table",
		TraceBodyLim:    2048,
		AuditMaxSize:    audit.DefaultMaxSizeBytes,
		resolveOperator: resolveOSOperator,
	}
}

func NewRootCmd() *cobra.Command {
	return newRootCmdWith(newDefaultFlags())
}

func newRootCmdWith(f *cliFlags) *cobra.Command {
	v, _, _ := getVersionInfo()
	cmd := &cobra.Command{
		Use:           "cfgov-cli",
		Short:         "Governed configuration CLI",
		Version:       v,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			applyGlobalFlags(f)
			f.preview = false
			f.commandCtx = c.Context()
			f.commandName = strings.ReplaceAll(c.CommandPath(), " ", ".")
			f.commandTime = time.Now()
			if f.Config != "" {
				cfgovctx.SetConfigPath(f.Config)
			}
			if err := validateOutput(f.Output); err != nil {
				return err
			}
			if _, err := trustedOperator(f); err != nil {
				return err
			}
			traceEndpoint, metricsEndpoint, insecure, ctxMeta, ctxName := resolveTelemetryConfig(f)
			f.telemetryStop = telemetry.Init(c.Context(), traceEndpoint, insecure, v)
			f.metricsStop = telemetry.InitMetrics(c.Context(), metricsEndpoint, insecure, v)
			spanCtx, span := telemetry.Tracer().Start(c.Context(), f.commandName)
			f.metricAttrs = telemetry.SpanAttributes(currentOperator(f), ctxName, ctxMeta.Env, "", "", ctxMeta.Protected, true, "")
			if ticketFingerprint, _ := sensitiveAuditFingerprint("telemetry:ticket", f.Ticket); ticketFingerprint != "" {
				f.metricAttrs = append(f.metricAttrs, attribute.String("cfgov.ticket_fingerprint", ticketFingerprint))
			}
			span.SetAttributes(f.metricAttrs...)
			f.commandCtx = spanCtx
			f.activeSpan = span
			return nil
		},
		PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
			return appendPreviewAudit(f)
		},
	}
	cmd.PersistentFlags().StringVar(&f.Config, "config", "", "Override context config path")
	cmd.PersistentFlags().StringVar(&f.Context, "context", "", "Temporarily use a named context for this command")
	cmd.PersistentFlags().StringVar(&f.Backend, "backend", "", "Backend override: nacos | apollo | etcd | k8s | consul")
	cmd.PersistentFlags().StringVar(&f.Server, "server", "", "Backend server URL")
	cmd.PersistentFlags().StringVar(&f.Username, "username", "", "Backend username")
	cmd.PersistentFlags().StringVar(&f.Password, "password", "", "Backend password")
	_ = cmd.PersistentFlags().MarkHidden("password")
	cmd.PersistentFlags().StringVarP(&f.Namespace, "namespace", "n", "", "Backend namespace")
	cmd.PersistentFlags().DurationVar(&f.Timeout, "timeout", 30*time.Second, "Request timeout")
	cmd.PersistentFlags().StringVarP(&f.Output, "output", "o", "table", "Output format: table | json | plain")
	cmd.PersistentFlags().BoolVar(&f.PlainHead, "plain-header", false, "Show headers in plain output")
	cmd.PersistentFlags().BoolVar(&f.Debug, "debug", false, "Enable debug logging")
	cmd.PersistentFlags().BoolVar(&f.Trace, "trace", false, "Enable trace logging (implies --debug)")
	cmd.PersistentFlags().BoolVar(&f.NoColor, "no-color", false, "Disable colored output")
	cmd.PersistentFlags().IntVar(&f.TraceBodyLim, "trace-body-limit", 2048, "Trace body byte limit (0 = unlimited)")
	_ = cmd.PersistentFlags().MarkHidden("trace-body-limit")
	cmd.PersistentFlags().BoolVar(&f.StrictNoChange, "strict-no-change", false, "Exit 13 (NO_CHANGE_REQUIRED) when a plan has no changes to apply")
	cmd.PersistentFlags().Int64Var(&f.AuditMaxSize, "audit-max-size", audit.DefaultMaxSizeBytes, "Active audit log rotation size in bytes")
	cmd.PersistentFlags().BoolVar(&f.DryRun, "dry-run", false, "Preview only, do not apply backend or local target mutations")
	cmd.PersistentFlags().BoolVar(&f.Plan, "plan", false, "Alias for --dry-run; takes precedence over confirmation flags")
	cmd.PersistentFlags().BoolVar(&f.Diff, "diff", false, "Include CLI-computed impact summary")
	cmd.PersistentFlags().BoolVar(&f.Yes, "yes", false, "Confirm write authorization")
	cmd.PersistentFlags().BoolVar(&f.Backup, "backup", false, "Backup current remote config before writing")
	cmd.PersistentFlags().BoolVar(&f.NoBackup, "no-backup", false, "Explicitly skip backup before writing")
	cmd.PersistentFlags().StringVar(&f.Ticket, "ticket", "", "Human-supplied change ticket")
	cmd.PersistentFlags().StringVar(&f.Operator, "operator", "", "Deprecated compatibility input; ignored for identity and authorization")
	cmd.PersistentFlags().StringVar(&f.Reason, "reason", "", "Change reason")
	cmd.PersistentFlags().BoolVar(&f.NonInter, "non-interactive", false, "Disable interactive confirmation")
	cmd.PersistentFlags().BoolVar(&f.AllowDel, "allow-production-config-delete", false, "Allow protected config delete")
	cmd.PersistentFlags().BoolVar(&f.AllowReconcile, "allow-production-reconcile", false, "Allow protected config reconcile without prune")
	cmd.PersistentFlags().BoolVar(&f.AllowPrune, "allow-production-prune", false, "Allow protected reconcile prune actions")
	cmd.PersistentFlags().BoolVar(&f.AllowNSDel, "allow-production-namespace-delete", false, "Allow protected namespace delete")
	cmd.PersistentFlags().BoolVar(&f.AllowSvcDereg, "allow-production-service-deregister", false, "Allow protected service deregister")
	cmd.PersistentFlags().BoolVar(&f.AllowRuleDel, "allow-production-rule-delete", false, "Allow protected Sentinel rule delete")
	cmd.PersistentFlags().BoolVar(&f.AllowFlagDel, "allow-production-flag-delete", false, "Allow protected feature flag delete")
	cmd.PersistentFlags().BoolVar(&f.AllowCtxChange, "allow-context-change", false, "Allow an R3 context create, replace, switch, import, or credential migration")
	cmd.PersistentFlags().BoolVar(&f.AllowCtxDelete, "allow-context-delete", false, "Allow an R3 context deletion")
	cmd.PersistentFlags().BoolVar(&f.AllowRoleChange, "allow-role-change", false, "Allow an R3 context role assignment or removal")
	cmd.PersistentFlags().BoolVar(&f.AllowAuditPrune, "allow-audit-prune", false, "Allow an R3 audit evidence pruning operation")
	cmd.PersistentFlags().BoolVar(&f.AllowAuditRepair, "allow-audit-repair", false, "Allow an R3 audit evidence repair operation")
	cmd.PersistentFlags().StringVar(&f.K8sKubeconfig, "k8s-kubeconfig", "", "Kubernetes kubeconfig path")
	cmd.PersistentFlags().StringVar(&f.K8sContext, "k8s-context", "", "Kubernetes kubeconfig context")
	cmd.PersistentFlags().StringVar(&f.OTLPEnd, "otel-endpoint", "", "OTLP trace endpoint")
	cmd.PersistentFlags().StringVar(&f.OTLPMetrics, "otel-metrics-endpoint", "", "OTLP metrics endpoint")
	cmd.PersistentFlags().BoolVar(&f.OTLPInsec, "otel-insecure", false, "Disable TLS for OTLP exporter")

	cmd.AddCommand(newContextCmd(f), newConfigCmd(f), newNamespaceCmd(f), newServiceCmd(f), newRuleCmd(f), newFlagCmd(f), newBackupCmd(f), newCapabilitiesCmd(f), newAuditCmd(f), newDoctorCmd(f), newCompletionCmd(f), newVersionCmd(f), newInstallCmd(f))
	setSuggestionsRecursive(cmd, 1)
	return cmd
}

func applyGlobalFlags(f *cliFlags) {
	if f.Trace {
		f.Debug = true
	}
	if f.NoColor {
		_ = os.Setenv("NO_COLOR", "1")
		color.NoColor = true
	}
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
			errorCode := string(apperrors.AsAppError(err).Code)
			f.activeSpan.SetAttributes(attribute.String("cfgov.error_code", errorCode))
			f.activeSpan.SetStatus(codes.Error, errorCode)
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
	if err == nil {
		stop()
		return
	}
	stop()
	exitWithCommandError(err)
}

func exitWithCommandError(err error) {
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
	if backendName == "consul" {
		backend, err := buildConsulBackend(f, name, item, server)
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
	server, username, password, err := resolveNacosAuth(commandContext(f), f, name, item, server)
	if err != nil {
		return nil, cfgovctx.Context{}, err
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
	case "consul":
		return os.Getenv("CONSUL_SERVER")
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

func buildConsulBackend(f *cliFlags, contextName string, item cfgovctx.Context, server string) (cfgov.Backend, error) {
	token := firstNonEmpty(f.Password, os.Getenv("CONSUL_TOKEN"))
	if token == "" {
		resolved, err := cfgovctx.ResolvePassword(commandContext(f), contextName, item)
		if err != nil {
			return nil, err
		}
		token = resolved
	}
	return consulBackend.New(consulBackend.Options{
		Server:        server,
		KeyPrefix:     firstNonEmpty(os.Getenv("CONSUL_KEY_PREFIX"), item.ConsulKeyPrefix),
		Namespace:     firstNonEmpty(f.Namespace, os.Getenv("CONSUL_NAMESPACE"), item.Namespace),
		RuleNamespace: firstNonEmpty(os.Getenv("CONSUL_RULE_NAMESPACE"), item.ConsulRuleNamespace),
		Token:         token,
		CACert:        firstNonEmpty(os.Getenv("CONSUL_CACERT"), item.ConsulCACert),
		ClientCert:    firstNonEmpty(os.Getenv("CONSUL_CLIENT_CERT"), item.ConsulClientCert),
		ClientKey:     firstNonEmpty(os.Getenv("CONSUL_CLIENT_KEY"), item.ConsulClientKey),
		Timeout:       f.Timeout,
		Trace:         f.Debug || f.Trace,
		TraceOut:      os.Stderr,
	})
}

func resolveNacosAuth(ctx context.Context, f *cliFlags, contextName string, item cfgovctx.Context, server string) (string, string, string, error) {
	cleanServer, urlUsername, urlPassword := nacosServerUserInfo(server)
	username := firstNonEmpty(f.Username, os.Getenv("NACOS_USERNAME"), item.Username, urlUsername)
	password := firstNonEmpty(f.Password, os.Getenv("NACOS_PASSWORD"))
	if password == "" && item.Password != "" {
		resolved, err := cfgovctx.ResolvePassword(ctx, contextName, item)
		if err != nil {
			return "", "", "", err
		}
		password = resolved
	}
	if password == "" && item.Password == "" {
		password = os.Getenv("CFGOV_PASSWORD")
	}
	if password == "" {
		password = urlPassword
	}
	return cleanServer, username, password, nil
}

func nacosServerUserInfo(server string) (string, string, string) {
	parsed, err := url.Parse(server)
	if err != nil || parsed.User == nil {
		return server, "", ""
	}
	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	parsed.User = nil
	return parsed.String(), username, password
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
	return authorizeForContext(f, base, meta, required, f.contextName())
}

func authorizeForContext(f *cliFlags, base safety.Risk, meta cfgovctx.Context, required safety.AllowFlag, contextName string) error {
	operator, operatorErr := trustedOperator(f)
	if operatorErr != nil {
		return operatorErr
	}
	if meta.RolesSource != "" && meta.RolesSource != "inline" || strings.TrimSpace(meta.RolesURL) != "" {
		err := apperrors.New(apperrors.CodeAuthorizationRequired, "authorization denied because remote role sources are not implemented; use inline roles", nil)
		telemetry.RecordAuthorizationDenied(commandContext(f), "authorization", nil)
		appendAuditWarnForContext(f, audit.EventAuthorizationDenied, contextName, meta, audit.EventTarget{ResourceType: "context", Resource: contextName}, audit.StatusDenied, "", err)
		return err
	}
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
		Validator:          ticketValidator(meta.TicketValidator, contextName, operator),
		RequiredAllowFlags: requiredAllow(required),
		GrantedAllowFlags: map[safety.AllowFlag]bool{
			allowProductionConfigDelete: f.AllowDel,
			allowProductionReconcile:    f.AllowReconcile,
			allowProductionPrune:        f.AllowPrune,
			allowProductionNamespaceDel: f.AllowNSDel,
			allowProductionServiceDereg: f.AllowSvcDereg,
			allowProductionRuleDelete:   f.AllowRuleDel,
			allowProductionFlagDelete:   f.AllowFlagDel,
			allowContextChange:          f.AllowCtxChange,
			allowContextDelete:          f.AllowCtxDelete,
			allowRoleChange:             f.AllowRoleChange,
			allowAuditPrune:             f.AllowAuditPrune,
			allowAuditRepair:            f.AllowAuditRepair,
		},
		Roles:    meta.Roles,
		Operator: operator,
	})
	if err != nil {
		telemetry.RecordAuthorizationDenied(commandContext(f), "authorization", nil)
		appendAuditWarnForContext(f, audit.EventAuthorizationDenied, contextName, meta, audit.EventTarget{ResourceType: "context", Resource: contextName}, audit.StatusDenied, "", err)
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

func isPlanOnly(f *cliFlags) bool {
	return f.DryRun || f.Plan
}

func runBeforeContextUpdate(f *cliFlags) {
	if f.beforeContextUpdate != nil {
		f.beforeContextUpdate()
	}
}

func markPreview(f *cliFlags) {
	f.preview = true
}

func isPreview(f *cliFlags) bool {
	return f.preview
}

func printLocalChangePlan(f *cliFlags, resourceType, action, target string, details map[string]any) error {
	markPreview(f)
	data := map[string]any{
		"resourceType": resourceType,
		"action":       action,
		"target":       target,
		"dryRun":       true,
	}
	for key, value := range details {
		data[key] = value
	}
	return newPrinter(f).JSONData("ChangePlan", data)
}

func appendAuditWarn(f *cliFlags, typ audit.EventType, ctx cfgovctx.Context, target audit.EventTarget, status, diff string, err error) {
	appendAuditWarnForContext(f, typ, f.contextName(), ctx, target, status, diff, err)
}

func appendAuditWarnForContext(f *cliFlags, typ audit.EventType, contextName string, ctx cfgovctx.Context, target audit.EventTarget, status, diff string, err error) {
	if err == nil && status == audit.StatusSuccess && isPreview(f) {
		return
	}
	path, pathErr := configuredAuditPath(f)
	if pathErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: audit path failed: %v\n", pathErr)
		return
	}
	evt := audit.Event{
		EventType: typ,
		Operator:  currentOperator(f),
		Context:   audit.EventContext{Name: contextName, Env: ctx.Env, Protected: ctx.Protected},
		Target:    target,
		Status:    status,
		Diff:      sanitizedAuditSummary(f, typ, diff),
	}
	if err != nil {
		appErr := apperrors.AsAppError(err)
		evt.Error = &audit.EventError{Code: string(appErr.Code)}
	}
	if appendErr := appendQueuedAuditEvent(f, path, evt); appendErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: audit write failed: %v\n", appendErr)
	}
}

type previewAuditRecord struct {
	audit.Event
	Preview bool `json:"preview"`
	DryRun  bool `json:"dryRun"`
}

func appendPreviewAudit(f *cliFlags) error {
	if !isPreview(f) {
		return nil
	}
	path, err := configuredAuditPath(f)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to resolve preview audit path", err)
	}
	meta, _, _ := resolvedContext(f)
	command := f.commandName
	record := previewAuditRecord{
		Event: audit.Event{
			EventType: audit.EventType("command.preview"),
			Operator:  currentOperator(f),
			Context:   audit.EventContext{Name: f.contextName(), Env: meta.Env, Protected: meta.Protected},
			Target:    audit.EventTarget{ResourceType: "command", Resource: command},
			Status:    auditStatusSkipped,
			Diff: "preview=true dryRun=true " +
				sanitizedAuditSummary(f, audit.EventType("command.preview"), "command="+command),
		},
		Preview: true,
		DryRun:  true,
	}
	if err := appendQueuedAuditRecord(f, path, func(timestamp time.Time) any {
		record.Timestamp = timestamp
		return record
	}); err != nil {
		return err
	}
	return nil
}

func sanitizedAuditSummary(f *cliFlags, eventType audit.EventType, detail string) string {
	parts := make([]string, 0, 6)
	if ticketFingerprint, ticketBytes := sensitiveAuditFingerprint("audit:ticket", f.Ticket); ticketFingerprint != "" {
		parts = append(parts, "ticketFingerprint="+ticketFingerprint, fmt.Sprintf("ticketBytes=%d", ticketBytes))
	}
	if reasonFingerprint, reasonBytes := sensitiveAuditFingerprint("audit:reason", f.Reason); reasonFingerprint != "" {
		parts = append(parts, "reasonFingerprint="+reasonFingerprint, fmt.Sprintf("reasonBytes=%d", reasonBytes))
	}
	if detail != "" {
		detail = redact.String(detail)
		parts = append(
			parts,
			"detailFingerprint="+mutationAuditFingerprint("audit:detail:"+string(eventType), []byte(detail)),
			fmt.Sprintf("detailBytes=%d", len([]byte(detail))),
		)
	}
	return strings.Join(parts, " ")
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
	operator, _ := trustedOperator(f)
	return operator
}

func trustedOperator(f *cliFlags) (string, error) {
	if strings.TrimSpace(f.trustedOperator) != "" {
		return f.trustedOperator, nil
	}
	resolver := f.resolveOperator
	if resolver == nil {
		resolver = resolveOSOperator
	}
	operator, err := resolver()
	if err != nil {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "trusted local operator identity is unavailable", err)
	}
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "trusted local operator identity is unavailable", nil)
	}
	f.trustedOperator = operator
	return operator, nil
}

func resolveOSOperator() (string, error) {
	user, err := osuser.Current()
	if err != nil {
		return "", err
	}
	if user == nil || strings.TrimSpace(user.Username) == "" {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "local OS username is unavailable", nil)
	}
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "local hostname is unavailable", nil)
	}
	return strings.TrimSpace(user.Username) + "@" + host, nil
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
