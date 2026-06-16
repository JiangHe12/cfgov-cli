package cfgov

import "context"

const DefaultGroup = "DEFAULT_GROUP"

type Coordinate struct {
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
}

type Blob struct {
	Coordinate Coordinate `json:"coordinate"`
	Content    []byte     `json:"-"`
	Revision   string     `json:"revision,omitempty"`
}

type PutRequest struct {
	Coordinate       Coordinate
	Content          []byte
	ContentType      string
	ExpectedRevision string
}

type DeleteRequest struct {
	Coordinate       Coordinate
	ExpectedRevision string
}

type ListOptions struct {
	Namespace string
	Prefix    string
	Limit     int
}

type ListItem struct {
	Coordinate Coordinate `json:"coordinate"`
	Revision   string     `json:"revision,omitempty"`
}

type Description struct {
	Backend   string `json:"backend"`
	Server    string `json:"server,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type Capabilities struct {
	Backend          string   `json:"backend"`
	ResourceTypes    []string `json:"resourceTypes"`
	Verbs            []string `json:"verbs"`
	SupportsCAS      bool     `json:"supportsCas"`
	SupportsRevision bool     `json:"supportsRevision"`
}

type Backend interface {
	Get(ctx context.Context, coord Coordinate) (Blob, error)
	Put(ctx context.Context, req PutRequest) (Blob, error)
	Delete(ctx context.Context, req DeleteRequest) error
	List(ctx context.Context, opts ListOptions) ([]ListItem, error)
	CurrentRevision(ctx context.Context, coord Coordinate) (string, error)
	Ping(ctx context.Context) error
	Describe() Description
	Capabilities() Capabilities
}
