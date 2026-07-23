package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type servicePlan struct {
	ResourceType string                `json:"resourceType"`
	Action       string                `json:"action"`
	Service      string                `json:"service"`
	IP           string                `json:"ip,omitempty"`
	Port         int                   `json:"port,omitempty"`
	Risk         safety.Risk           `json:"risk"`
	Options      cfgov.InstanceOptions `json:"options,omitempty"`
	Impact       string                `json:"impact"`
	DryRun       bool                  `json:"dryRun"`
}

func newServiceCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Govern service registry instances", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(serviceListCmd(f), serviceGetCmd(f), serviceInstancesCmd(f), serviceRegisterCmd(f), serviceDeregisterCmd(f))
	return cmd
}

func serviceListCmd(f *cliFlags) *cobra.Command {
	var page, pageSize int
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List services",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			readResult, err := runMandatoryBackendRead(
				f,
				"service.list",
				"service",
				"*",
				map[string]int{
					"page":     page,
					"pageSize": pageSize,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (cfgov.ServiceList, error) {
					registry, registryErr := serviceRegistry(backend)
					if registryErr != nil {
						return cfgov.ServiceList{}, registryErr
					}
					return registry.ListServices(cmd.Context(), page, pageSize)
				},
				func(result cfgov.ServiceList) int { return len(result.Names) },
			)
			if err != nil {
				return err
			}
			result := readResult.Value
			target := readResult.operationTarget()
			p := newPrinter(f)
			if f.Output == "json" {
				return targetJSONData(f, "ServiceList", result, target, operationTargetRead)
			}
			if err := printOperationTarget(p, target, operationTargetRead); err != nil {
				return err
			}
			rows := make([][]string, 0, len(result.Names))
			for _, name := range result.Names {
				rows = append(rows, []string{name})
			}
			return p.Table([]string{"SERVICE"}, rows)
		},
	}
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Items per page")
	return cmd
}

func serviceGetCmd(f *cliFlags) *cobra.Command {
	var service string
	cmd := &cobra.Command{
		Use:   "get --service <name>",
		Short: "Get service metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateServiceName(service); err != nil {
				return err
			}
			readResult, err := runMandatoryBackendRead(
				f,
				"service.get",
				"service",
				service,
				map[string]string{
					"service": service,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (map[string]any, error) {
					registry, registryErr := serviceRegistry(backend)
					if registryErr != nil {
						return nil, registryErr
					}
					return registry.GetService(cmd.Context(), service)
				},
				func(map[string]any) int { return 1 },
			)
			if err != nil {
				return err
			}
			return targetJSONData(f, "ServiceItem", readResult.Value, readResult.operationTarget(), operationTargetRead)
		},
	}
	cmd.Flags().StringVarP(&service, "service", "s", "", "Service name")
	_ = cmd.MarkFlagRequired("service")
	return cmd
}

func serviceInstancesCmd(f *cliFlags) *cobra.Command {
	var service, group string
	cmd := &cobra.Command{
		Use:   "instances --service <name>",
		Short: "List service instances",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateServiceName(service); err != nil {
				return err
			}
			readResult, err := runMandatoryBackendRead(
				f,
				"service.instances",
				"service",
				service,
				map[string]string{
					"service": service,
					"group":   group,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) ([]cfgov.ServiceInstance, error) {
					registry, registryErr := serviceRegistry(backend)
					if registryErr != nil {
						return nil, registryErr
					}
					return registry.ListInstances(cmd.Context(), service, group)
				},
				func(items []cfgov.ServiceInstance) int { return len(items) },
			)
			if err != nil {
				return err
			}
			items := readResult.Value
			target := readResult.operationTarget()
			p := newPrinter(f)
			if f.Output == "json" {
				return targetJSONList(f, "ServiceInstanceList", items, len(items), 1, len(items), target)
			}
			if err := printOperationTarget(p, target, operationTargetRead); err != nil {
				return err
			}
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{item.IP, strconv.Itoa(item.Port), fmt.Sprint(item.Healthy), fmt.Sprint(item.Enabled), fmt.Sprint(item.Weight)})
			}
			return p.Table([]string{"IP", "PORT", "HEALTHY", "ENABLED", "WEIGHT"}, rows)
		},
	}
	cmd.Flags().StringVarP(&service, "service", "s", "", "Service name")
	cmd.Flags().StringVar(&group, "group", "", "Group name")
	_ = cmd.MarkFlagRequired("service")
	return cmd
}

func serviceRegisterCmd(f *cliFlags) *cobra.Command {
	opts := instanceFlagSet{}
	cmd := &cobra.Command{
		Use:   "register --service <name> --ip <ip> --port <port>",
		Short: "Register a service instance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctxMeta, ctxName, plan, err := serviceMutationInputs(f, opts, "register", safety.R1)
			if err != nil {
				return err
			}
			if isPlanOnly(f) {
				markPreview(f)
				plan.DryRun = true
				return targetJSONData(f, "ChangePlan", plan, operationTargetFromResolvedContext(f, ctxMeta, ctxName), operationTargetWrite)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			metadata := mutationValueMetadata("service.register", plan)
			metadata.Items = 1
			metadata.Creates = 1
			execution, err := runAuthorizedBackendMutation(f, ctxMeta, ctxName, safety.R1, "", mutationAuditSpec{
				Action:   "service.register",
				Target:   audit.EventTarget{ResourceType: "service", Resource: plan.Service},
				Metadata: metadata,
			}, func(backend cfgov.Backend, _ cfgovctx.Context) error {
				registry, registryErr := serviceRegistry(backend)
				if registryErr != nil {
					return registryErr
				}
				warnEphemeralServiceRegister(plan.Options)
				operationErr := registry.RegisterInstance(cmd.Context(), plan.Service, plan.IP, plan.Port, plan.Options)
				appendServiceAudit(f, ctxMeta, "register", plan.Service, auditStatus(operationErr), plan.Impact, operationErr)
				return operationErr
			})
			if err != nil {
				return err
			}
			return targetJSONData(f, "ChangeResult", map[string]any{"resourceType": "service", "action": "register", "service": plan.Service, "ip": plan.IP, "port": plan.Port}, operationTargetFromDescription(execution.ContextName, execution.Backend.Describe()), operationTargetWrite)
		},
	}
	opts.bind(cmd)
	return cmd
}

func serviceDeregisterCmd(f *cliFlags) *cobra.Command {
	opts := instanceFlagSet{}
	cmd := &cobra.Command{
		Use:   "deregister --service <name> --ip <ip> --port <port>",
		Short: "Deregister a service instance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctxMeta, ctxName, plan, err := serviceMutationInputs(f, opts, "deregister", safety.R2)
			if err != nil {
				return err
			}
			if isPlanOnly(f) {
				markPreview(f)
				plan.DryRun = true
				return targetJSONData(f, "ChangePlan", plan, operationTargetFromResolvedContext(f, ctxMeta, ctxName), operationTargetWrite)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			metadata := mutationValueMetadata("service.deregister", plan)
			metadata.Items = 1
			metadata.Deletes = 1
			execution, err := runAuthorizedBackendMutation(f, ctxMeta, ctxName, safety.R2, allowProductionServiceDereg, mutationAuditSpec{
				Action:   "service.deregister",
				Target:   audit.EventTarget{ResourceType: "service", Resource: plan.Service},
				Metadata: metadata,
			}, func(backend cfgov.Backend, _ cfgovctx.Context) error {
				registry, registryErr := serviceRegistry(backend)
				if registryErr != nil {
					return registryErr
				}
				operationErr := registry.DeregisterInstance(cmd.Context(), plan.Service, plan.IP, plan.Port, plan.Options)
				appendServiceAudit(f, ctxMeta, "deregister", plan.Service, auditStatus(operationErr), plan.Impact, operationErr)
				return operationErr
			})
			if err != nil {
				return err
			}
			return targetJSONData(f, "ChangeResult", map[string]any{"resourceType": "service", "action": "deregister", "service": plan.Service, "ip": plan.IP, "port": plan.Port}, operationTargetFromDescription(execution.ContextName, execution.Backend.Describe()), operationTargetWrite)
		},
	}
	opts.bind(cmd)
	return cmd
}

type instanceFlagSet struct {
	service    string
	ip         string
	port       int
	group      string
	cluster    string
	weight     float64
	metadata   []string
	persistent bool
	ephemeral  bool
}

func (s *instanceFlagSet) bind(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&s.service, "service", "s", "", "Service name")
	cmd.Flags().StringVar(&s.ip, "ip", "", "Instance IP")
	cmd.Flags().IntVar(&s.port, "port", 0, "Instance port")
	cmd.Flags().StringVar(&s.group, "group", "", "Group name")
	cmd.Flags().StringVar(&s.cluster, "cluster", "", "Cluster name")
	cmd.Flags().Float64Var(&s.weight, "weight", 0, "Instance weight")
	cmd.Flags().StringArrayVar(&s.metadata, "metadata", nil, "Instance metadata key=value")
	cmd.Flags().BoolVar(&s.persistent, "persistent", false, "Register as persistent instance")
	cmd.Flags().BoolVar(&s.ephemeral, "ephemeral", false, "Register as ephemeral instance")
	_ = cmd.MarkFlagRequired("service")
	_ = cmd.MarkFlagRequired("ip")
	_ = cmd.MarkFlagRequired("port")
}

func serviceMutationInputs(f *cliFlags, flags instanceFlagSet, action string, risk safety.Risk) (cfgovctx.Context, string, servicePlan, error) {
	if err := validateServiceName(flags.service); err != nil {
		return cfgovctx.Context{}, "", servicePlan{}, err
	}
	if net.ParseIP(flags.ip) == nil {
		return cfgovctx.Context{}, "", servicePlan{}, apperrors.New(apperrors.CodeUsageError, "invalid instance IP", nil)
	}
	if flags.port <= 0 || flags.port > 65535 {
		return cfgovctx.Context{}, "", servicePlan{}, apperrors.New(apperrors.CodeUsageError, "--port must be between 1 and 65535", nil)
	}
	options, err := instanceOptions(flags)
	if err != nil {
		return cfgovctx.Context{}, "", servicePlan{}, err
	}
	ctxMeta, ctxName, err := resolvedContext(f)
	if err != nil {
		return cfgovctx.Context{}, "", servicePlan{}, err
	}
	impact := fmt.Sprintf("%s service instance %s %s:%d", action, flags.service, flags.ip, flags.port)
	return ctxMeta, ctxName, servicePlan{
		ResourceType: "service",
		Action:       action,
		Service:      flags.service,
		IP:           flags.ip,
		Port:         flags.port,
		Risk:         risk,
		Options:      options,
		Impact:       impact,
	}, nil
}

func instanceOptions(flags instanceFlagSet) (cfgov.InstanceOptions, error) {
	if flags.persistent && flags.ephemeral {
		return cfgov.InstanceOptions{}, apperrors.New(apperrors.CodeUsageError, "--persistent and --ephemeral are mutually exclusive", nil)
	}
	metadata, err := parseMetadata(flags.metadata)
	if err != nil {
		return cfgov.InstanceOptions{}, err
	}
	var ephemeral *bool
	if flags.persistent || flags.ephemeral {
		value := flags.ephemeral
		ephemeral = &value
	}
	return cfgov.InstanceOptions{GroupName: flags.group, Cluster: flags.cluster, Weight: flags.weight, Ephemeral: ephemeral, Metadata: metadata}, nil
}

func parseMetadata(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, apperrors.New(apperrors.CodeUsageError, "--metadata must use key=value", nil)
		}
		out[key] = val
	}
	return out, nil
}

func serviceRegistry(backend cfgov.Backend) (cfgov.ServiceRegistry, error) {
	registry, ok := backend.(cfgov.ServiceRegistry)
	if !ok {
		return nil, apperrors.New(apperrors.CodeNotImplemented, "backend does not support service registry", nil)
	}
	return registry, nil
}

func authorizeServiceDeregister(f *cliFlags, meta cfgovctx.Context) error {
	return authorize(f, safety.R2, meta, allowProductionServiceDereg)
}

func warnEphemeralServiceRegister(options cfgov.InstanceOptions) {
	if options.Ephemeral != nil && !*options.Ephemeral {
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, "warning: registering as ephemeral; Nacos may remove this instance after no heartbeat. Use --persistent for long-lived registrations.")
}

func validateServiceName(service string) error {
	if strings.TrimSpace(service) == "" || strings.ContainsAny(service, "\r\n") {
		return apperrors.New(apperrors.CodeUsageError, "invalid service name", nil)
	}
	return nil
}

func appendServiceAudit(f *cliFlags, ctxMeta cfgovctx.Context, verb, service, status, impact string, err error) {
	appendAuditWarn(f, audit.EventType("service."+verb), ctxMeta, audit.EventTarget{ResourceType: "service", Resource: service}, status, impact, err)
}
