package cmd

import (
	"net/url"
	"os"
	"strings"

	"github.com/JiangHe12/opskit-core/printer"
	"github.com/JiangHe12/opskit-core/redact"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type operationTargetMode string

const (
	operationTargetRead  operationTargetMode = "read"
	operationTargetWrite operationTargetMode = "write"
)

type operationTarget struct {
	Context   string `json:"context"`
	Backend   string `json:"backend"`
	Server    string `json:"server"`
	Namespace string `json:"namespace"`
}

func operationTargetFromBackend(f *cliFlags, backend cfgov.Backend) operationTarget {
	return operationTargetFromDescription(f.contextName(), backend.Describe())
}

func operationTargetFromDescription(contextName string, desc cfgov.Description) operationTarget {
	return operationTarget{
		Context:   contextName,
		Backend:   desc.Backend,
		Server:    sanitizeTargetServer(desc.Server),
		Namespace: desc.Namespace,
	}
}

func operationTargetFromContext(f *cliFlags, meta cfgovctx.Context) operationTarget {
	backendName := firstNonEmpty(f.Backend, meta.Backend, "nacos")
	return operationTarget{
		Context:   f.contextName(),
		Backend:   backendName,
		Server:    sanitizeTargetServer(firstNonEmpty(f.Server, backendServerEnv(backendName), meta.Server)),
		Namespace: targetNamespace(f, meta, backendName),
	}
}

func printOperationTarget(p *printer.Printer, target operationTarget, mode operationTargetMode) {
	label := "TARGET"
	if mode == operationTargetWrite {
		label = "WRITE TARGET"
	}
	p.TargetHeader(label, [][2]string{
		{"context", target.Context},
		{"backend", target.Backend},
		{"server", target.Server},
		{"namespace", target.Namespace},
	})
}

func targetDataForOutput(f *cliFlags, data any, target operationTarget) any {
	if f.Output == "json" {
		return printer.WithTarget(data, target)
	}
	return data
}

func targetJSONData(f *cliFlags, kind string, data any, target operationTarget, mode operationTargetMode) error {
	p := newPrinter(f)
	printOperationTarget(p, target, mode)
	return p.JSONData(kind, targetDataForOutput(f, data, target))
}

func targetJSONList(f *cliFlags, kind string, items any, total, page, pageSize int, target operationTarget) error {
	return newPrinter(f).JSONListEnvelope(printer.JSONListEnvelope{
		Kind:      kind,
		Items:     items,
		Total:     total,
		Page:      page,
		PageSize:  pageSize,
		Truncated: false,
		Target:    target,
	})
}

func targetNamespace(f *cliFlags, meta cfgovctx.Context, backendName string) string {
	switch backendName {
	case "apollo":
		return firstNonEmpty(f.Namespace, os.Getenv("APOLLO_NAMESPACE"), meta.ApolloNamespace, meta.Namespace)
	case "etcd":
		return firstNonEmpty(f.Namespace, os.Getenv("ETCD_NAMESPACE"), meta.Namespace)
	case "consul":
		return firstNonEmpty(f.Namespace, os.Getenv("CONSUL_NAMESPACE"), meta.Namespace)
	case "nacos":
		return firstNonEmpty(f.Namespace, os.Getenv("NACOS_NAMESPACE"), meta.Namespace)
	default:
		return firstNonEmpty(f.Namespace, meta.Namespace)
	}
}

func sanitizeTargetServer(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	parsed, err := url.Parse(server)
	if err == nil && parsed.User != nil {
		parsed.User = nil
		server = parsed.String()
	}
	return redact.String(server)
}
