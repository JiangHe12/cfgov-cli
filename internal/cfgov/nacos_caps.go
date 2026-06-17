package cfgov

import "context"

type NamespaceItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ConfigCount int    `json:"configCount,omitempty"`
}

type NamespaceManager interface {
	ListNamespaces(ctx context.Context) ([]NamespaceItem, error)
	CreateNamespace(ctx context.Context, id, name, description string) error
	UpdateNamespace(ctx context.Context, id, name, description string) error
	DeleteNamespace(ctx context.Context, id string) error
	NamespaceConfigCount(ctx context.Context, id string) (int, error)
}

type ServiceList struct {
	Count int      `json:"count"`
	Names []string `json:"names"`
}

type ServiceInstance struct {
	IP       string            `json:"ip"`
	Port     int               `json:"port"`
	Healthy  bool              `json:"healthy"`
	Enabled  bool              `json:"enabled"`
	Weight   float64           `json:"weight"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type InstanceOptions struct {
	GroupName string            `json:"groupName,omitempty"`
	Cluster   string            `json:"cluster,omitempty"`
	Weight    float64           `json:"weight,omitempty"`
	Healthy   *bool             `json:"healthy,omitempty"`
	Enabled   *bool             `json:"enabled,omitempty"`
	Ephemeral *bool             `json:"ephemeral,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type ServiceRegistry interface {
	ListServices(ctx context.Context, page, pageSize int) (ServiceList, error)
	GetService(ctx context.Context, name string) (map[string]any, error)
	ListInstances(ctx context.Context, name, group string) ([]ServiceInstance, error)
	RegisterInstance(ctx context.Context, service, ip string, port int, opts InstanceOptions) error
	DeregisterInstance(ctx context.Context, service, ip string, port int, opts InstanceOptions) error
}
