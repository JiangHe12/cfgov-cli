package cfgovctx

import (
	"context"
	"fmt"

	"github.com/JiangHe12/opskit-core/credstore"
	corectx "github.com/JiangHe12/opskit-core/ctx"
)

const SupportedContextAPIVersion = "cfgov-cli.io/context/v1"

type Context struct {
	corectx.Base        `yaml:",inline"`
	Backend             string `yaml:"backend"`
	Namespace           string `yaml:"namespace,omitempty"`
	ApolloAppID         string `yaml:"apolloAppId,omitempty"`
	ApolloEnv           string `yaml:"apolloEnv,omitempty"`
	ApolloCluster       string `yaml:"apolloCluster,omitempty"`
	ApolloNamespace     string `yaml:"apolloNamespace,omitempty"`
	ApolloRuleNamespace string `yaml:"apolloRuleNamespace,omitempty"`
	EtcdKeyPrefix       string `yaml:"etcdKeyPrefix,omitempty"`
	EtcdRuleNamespace   string `yaml:"etcdRuleNamespace,omitempty"`
	EtcdCACert          string `yaml:"etcdCaCert,omitempty"`
	EtcdClientCert      string `yaml:"etcdClientCert,omitempty"`
	EtcdClientKey       string `yaml:"etcdClientKey,omitempty"`
	K8sKubeconfig       string `yaml:"k8sKubeconfig,omitempty"`
	K8sContext          string `yaml:"k8sContext,omitempty"`
}

func (c *Context) base() *corectx.Base { return &c.Base }

var store = corectx.NewStore(func(c *Context) *corectx.Base {
	if c == nil {
		return nil
	}
	return c.base()
})

func Configure() {
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".cfgov-cli"})
	credstore.Configure(credstore.Options{
		MasterPasswordEnv:     "CFGOV_CLI_CREDENTIAL_PASSPHRASE",
		PromptName:            "cfgov-cli",
		ConfigDirName:         ".cfgov-cli",
		KeychainService:       "cfgov-cli",
		KeychainAccountPrefix: "cfgov-cli:",
		EncryptedFileMagic:    []byte("CFGOV001"), // #nosec G101 -- file-format magic, not a secret.
	})
}

func SetConfigPath(path string) { corectx.SetConfigPath(path) }

func Load() (*corectx.Config[Context], error) { return store.Load() }

func Current() (*Context, string, error) { return store.Current() }

func Set(name string, item Context) error { return store.SetContext(name, item) }

func Use(name string) error { return store.UseContext(name) }

func Delete(name string) error { return store.DeleteContext(name) }

func ResolvePassword(ctx context.Context, name string, item Context) (string, error) {
	return item.ResolvePasswordContext(ctx, name)
}

func StoreCredential(ctx context.Context, name, backendName, password string, item Context) (Context, error) {
	if backendName == "" || backendName == "plain-yaml" {
		item.Password = password
		item.CredentialBackend = backendName
		return item, nil
	}
	backend, err := credstore.New(backendName)
	if err != nil {
		return item, err
	}
	if err := backend.Put(ctx, name, password); err != nil {
		return item, fmt.Errorf("store credential: %w", err)
	}
	item.Password = credstore.EncodeRef(backendName)
	item.CredentialBackend = backendName
	return item, nil
}
