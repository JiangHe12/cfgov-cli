package cfgov

import (
	"context"
	"time"
)

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
	Group     string
	Query     string
	Prefix    string
	Page      int
	PageSize  int
	Limit     int
}

type ListItem struct {
	Coordinate Coordinate `json:"coordinate"`
	Revision   string     `json:"revision,omitempty"`
	Type       string     `json:"type,omitempty"`
}

type HistoryOptions struct {
	Page     int
	PageSize int
}

type HistoryItem struct {
	ID           string `json:"id"`
	OpType       string `json:"opType"`
	ModifiedTime string `json:"modifiedTime"`
	DataID       string `json:"dataId"`
	Group        string `json:"group"`
	Operator     string `json:"operator,omitempty"`
}

type WatchOptions struct {
	LongPoll time.Duration
}

type WatchEvent struct {
	Coordinate Coordinate `json:"coordinate"`
	Revision   string     `json:"revision"`
	Changed    bool       `json:"changed"`
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
	SupportsHistory  bool     `json:"supportsHistory"`
	SupportsWatch    bool     `json:"supportsWatch"`
	SupportsRules    bool     `json:"supportsRules"`
	SupportsFlags    bool     `json:"supportsFlags"`
}

type Backend interface {
	ValidateKey(key string) error
	Get(ctx context.Context, coord Coordinate) (Blob, error)
	Put(ctx context.Context, req PutRequest) (Blob, error)
	Delete(ctx context.Context, req DeleteRequest) error
	List(ctx context.Context, opts ListOptions) ([]ListItem, error)
	History(ctx context.Context, coord Coordinate, opts HistoryOptions) ([]HistoryItem, int, error)
	Watch(ctx context.Context, coord Coordinate, revision string, opts WatchOptions) (WatchEvent, error)
	CurrentRevision(ctx context.Context, coord Coordinate) (string, error)
	Ping(ctx context.Context) error
	Describe() Description
	Capabilities() Capabilities
}

type RuleStore interface {
	RuleCoordinate(app, ruleType string) (Coordinate, error)
}

type FlagStore interface {
	FlagCoordinate(app string) (Coordinate, error)
}
