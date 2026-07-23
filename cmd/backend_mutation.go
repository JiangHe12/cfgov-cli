package cmd

import (
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type backendMutationExecution struct {
	Backend     cfgov.Backend
	Context     cfgovctx.Context
	ContextName string
}

// runAuthorizedBackendMutation keeps client construction behind both the
// elevated authorization decision and the durable mutation intent.
func runAuthorizedBackendMutation(
	f *cliFlags,
	contextMeta cfgovctx.Context,
	contextName string,
	risk safety.Risk,
	required safety.AllowFlag,
	spec mutationAuditSpec,
	operation func(cfgov.Backend, cfgovctx.Context) error,
) (backendMutationExecution, error) {
	var zero backendMutationExecution
	if err := authorizeForContext(f, risk, contextMeta, required, contextName); err != nil {
		return zero, err
	}
	spec.Context = contextMeta
	spec.ContextName = contextName
	mutation, err := beginMutationAudit(f, spec)
	if err != nil {
		return zero, err
	}
	backend, builtContext, operationErr := buildBackendForResolvedContext(f, contextMeta, contextName)
	if operationErr == nil {
		operationErr = operation(backend, builtContext)
	}
	if auditErr := finishMutationAudit(mutation, mutationAuditOutcome{}, operationErr); auditErr != nil {
		return zero, auditErr
	}
	return backendMutationExecution{
		Backend:     backend,
		Context:     builtContext,
		ContextName: contextName,
	}, nil
}
