package nacos

import (
	"context"
	"crypto/md5" //nolint:gosec // Nacos revisions are MD5 content fingerprints, not trust anchors.
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

type Backend struct {
	client *api.Client
	server string
}

func New(client *api.Client, server string) *Backend {
	return &Backend{client: client, server: strings.TrimRight(server, "/")}
}

var (
	_ cfgov.Backend          = (*Backend)(nil)
	_ cfgov.NamespaceManager = (*Backend)(nil)
	_ cfgov.ServiceRegistry  = (*Backend)(nil)
	_ cfgov.RuleStore        = (*Backend)(nil)
	_ cfgov.FlagStore        = (*Backend)(nil)
)

func (b *Backend) ValidateKey(key string) error {
	_, err := cfgov.ParseNacosKey(key)
	return err
}

func (b *Backend) Get(ctx context.Context, coord cfgov.Coordinate) (cfgov.Blob, error) {
	if err := b.requireNamespace(coord.Namespace); err != nil {
		return cfgov.Blob{}, err
	}
	key, err := cfgov.ParseNacosKey(coord.Key)
	if err != nil {
		return cfgov.Blob{}, err
	}
	content, err := b.client.GetConfig(ctx, key.DataID, key.Group)
	if err != nil {
		return cfgov.Blob{}, err
	}
	return cfgov.Blob{
		Coordinate: coord,
		Content:    []byte(content),
		Revision:   md5Hex([]byte(content)),
	}, nil
}

func (b *Backend) Put(ctx context.Context, req cfgov.PutRequest) (cfgov.Blob, error) {
	if err := b.requireNamespace(req.Coordinate.Namespace); err != nil {
		return cfgov.Blob{}, err
	}
	if err := b.checkCAS(ctx, req.Coordinate, req.ExpectedRevision); err != nil {
		return cfgov.Blob{}, err
	}
	key, err := cfgov.ParseNacosKey(req.Coordinate.Key)
	if err != nil {
		return cfgov.Blob{}, err
	}
	if err := b.client.PublishConfig(ctx, key.DataID, key.Group, string(req.Content), req.ContentType); err != nil {
		return cfgov.Blob{}, err
	}
	return cfgov.Blob{Coordinate: req.Coordinate, Content: req.Content, Revision: md5Hex(req.Content)}, nil
}

func (b *Backend) Delete(ctx context.Context, req cfgov.DeleteRequest) error {
	if err := b.requireNamespace(req.Coordinate.Namespace); err != nil {
		return err
	}
	if err := b.checkCAS(ctx, req.Coordinate, req.ExpectedRevision); err != nil {
		return err
	}
	key, err := cfgov.ParseNacosKey(req.Coordinate.Key)
	if err != nil {
		return err
	}
	return b.client.DeleteConfig(ctx, key.DataID, key.Group)
}

func (b *Backend) List(ctx context.Context, opts cfgov.ListOptions) ([]cfgov.ListItem, error) {
	if err := b.requireNamespace(opts.Namespace); err != nil {
		return nil, err
	}
	if opts.Query != "" {
		if err := b.ValidateKey(opts.Query); err != nil {
			return nil, err
		}
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	if opts.Page > 0 || opts.PageSize > 0 {
		page := opts.Page
		if page <= 0 {
			page = 1
		}
		pageSize := opts.PageSize
		if pageSize <= 0 {
			pageSize = 20
		}
		paged, err := b.client.ListConfigs(ctx, opts.Group, firstNonEmpty(opts.Query, opts.Prefix), page, pageSize)
		if err != nil {
			return nil, err
		}
		return listItems(opts.Namespace, paged.PageItems), nil
	}
	list, _, err := b.client.ListConfigsAll(ctx, opts.Group, firstNonEmpty(opts.Query, opts.Prefix), 50, limit)
	if err != nil {
		return nil, err
	}
	return listItems(opts.Namespace, list.PageItems), nil
}

func listItems(namespace string, pageItems []api.ConfigItem) []cfgov.ListItem {
	items := make([]cfgov.ListItem, 0, len(pageItems))
	for _, item := range pageItems {
		items = append(items, cfgov.ListItem{
			Coordinate: cfgov.Coordinate{Namespace: namespace, Key: cfgov.FormatNacosKey(item.Group, item.DataID)},
			Revision:   item.MD5,
			Type:       item.Type,
		})
	}
	return items
}

func (b *Backend) History(ctx context.Context, coord cfgov.Coordinate, opts cfgov.HistoryOptions) ([]cfgov.HistoryItem, int, error) {
	if err := b.requireNamespace(coord.Namespace); err != nil {
		return nil, 0, err
	}
	key, err := cfgov.ParseNacosKey(coord.Key)
	if err != nil {
		return nil, 0, err
	}
	items, total, err := b.client.GetHistory(ctx, key.DataID, key.Group, opts.Page, opts.PageSize)
	if err != nil {
		return nil, 0, err
	}
	out := make([]cfgov.HistoryItem, 0, len(items))
	for _, item := range items {
		out = append(out, cfgov.HistoryItem{
			ID:           item.ID,
			OpType:       item.OpType,
			ModifiedTime: item.LastModified,
			DataID:       item.DataID,
			Group:        item.Group,
			Operator:     item.SrcUser,
		})
	}
	return out, total, nil
}

func (b *Backend) HistoryBlob(ctx context.Context, coord cfgov.Coordinate, historyID string) (cfgov.Blob, error) {
	if err := b.requireNamespace(coord.Namespace); err != nil {
		return cfgov.Blob{}, err
	}
	key, err := cfgov.ParseNacosKey(coord.Key)
	if err != nil {
		return cfgov.Blob{}, err
	}
	content, err := b.client.GetHistoryConfig(ctx, key.DataID, key.Group, historyID)
	if err != nil {
		return cfgov.Blob{}, err
	}
	return cfgov.Blob{Coordinate: coord, Content: []byte(content), Revision: md5Hex([]byte(content))}, nil
}

func (b *Backend) Watch(ctx context.Context, coord cfgov.Coordinate, revision string, opts cfgov.WatchOptions) (cfgov.WatchEvent, error) {
	if err := b.requireNamespace(coord.Namespace); err != nil {
		return cfgov.WatchEvent{}, err
	}
	key, err := cfgov.ParseNacosKey(coord.Key)
	if err != nil {
		return cfgov.WatchEvent{}, err
	}
	longPoll := opts.LongPoll
	if longPoll <= 0 {
		longPoll = 30 * time.Second
	}
	changed, err := b.client.ListenConfig(ctx, key.DataID, key.Group, revision, longPoll)
	if err != nil {
		return cfgov.WatchEvent{}, err
	}
	nextRevision := revision
	if changed {
		nextRevision, err = b.CurrentRevision(ctx, coord)
		if err != nil {
			return cfgov.WatchEvent{}, err
		}
	}
	return cfgov.WatchEvent{Coordinate: coord, Revision: nextRevision, Changed: changed}, nil
}

func (b *Backend) CurrentRevision(ctx context.Context, coord cfgov.Coordinate) (string, error) {
	blob, err := b.Get(ctx, coord)
	if err != nil {
		return "", err
	}
	return blob.Revision, nil
}

func (b *Backend) Ping(ctx context.Context) error {
	return b.client.Ping(ctx)
}

func (b *Backend) Describe() cfgov.Description {
	return cfgov.Description{Backend: "nacos", Server: b.server, Namespace: b.client.Namespace()}
}

func (b *Backend) Capabilities() cfgov.Capabilities {
	return cfgov.Capabilities{
		Backend:          "nacos",
		ResourceTypes:    []string{"config", "namespace", "service", "rule", "flag"},
		Verbs:            []string{"get", "list", "diff", "validate", "pull", "history", "listen", "push", "delete"},
		SupportsCAS:      true,
		SupportsRevision: true,
		SupportsHistory:  true,
		SupportsWatch:    true,
		SupportsRules:    true,
		SupportsFlags:    true,
	}
}

func (b *Backend) RuleCoordinate(app, ruleType string) (cfgov.Coordinate, error) {
	parsed, err := rule.ParseType(ruleType)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	key, err := rule.NacosKey(app, parsed)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	if _, err := cfgov.ParseNacosKey(key); err != nil {
		return cfgov.Coordinate{}, err
	}
	return cfgov.Coordinate{Namespace: b.client.Namespace(), Key: key}, nil
}

func (b *Backend) FlagCoordinate(app string) (cfgov.Coordinate, error) {
	key, err := flag.NacosKey(app)
	if err != nil {
		return cfgov.Coordinate{}, err
	}
	if _, err := cfgov.ParseNacosKey(key); err != nil {
		return cfgov.Coordinate{}, err
	}
	return cfgov.Coordinate{Namespace: b.client.Namespace(), Key: key}, nil
}

func (b *Backend) ListNamespaces(ctx context.Context) ([]cfgov.NamespaceItem, error) {
	items, err := b.client.ListNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cfgov.NamespaceItem, 0, len(items))
	for _, item := range items {
		out = append(out, cfgov.NamespaceItem{
			ID:          item.Namespace,
			Name:        item.NamespaceShowName,
			Description: item.NamespaceDesc,
			ConfigCount: item.ConfigCount,
		})
	}
	return out, nil
}

func (b *Backend) CreateNamespace(ctx context.Context, id, name, description string) error {
	return b.client.CreateNamespace(ctx, id, name, description)
}

func (b *Backend) UpdateNamespace(ctx context.Context, id, name, description string) error {
	return b.client.UpdateNamespace(ctx, id, name, description)
}

func (b *Backend) DeleteNamespace(ctx context.Context, id string) error {
	return b.client.DeleteNamespace(ctx, id)
}

func (b *Backend) NamespaceConfigCount(ctx context.Context, id string) (int, error) {
	client := b.client.WithNamespace(id)
	list, truncated, err := client.ListConfigsAll(ctx, "", "", 100, 100000)
	if err != nil {
		return 0, err
	}
	if list.TotalCount > 0 && !truncated {
		return list.TotalCount, nil
	}
	return len(list.PageItems), nil
}

func (b *Backend) ListServices(ctx context.Context, page, pageSize int) (cfgov.ServiceList, error) {
	result, err := b.client.ListServices(ctx, page, pageSize)
	if err != nil {
		return cfgov.ServiceList{}, err
	}
	return cfgov.ServiceList{Count: result.Count, Names: result.Doms}, nil
}

func (b *Backend) GetService(ctx context.Context, name string) (map[string]any, error) {
	return b.client.GetService(ctx, name)
}

func (b *Backend) ListInstances(ctx context.Context, name, group string) ([]cfgov.ServiceInstance, error) {
	items, err := b.client.ListInstances(ctx, name, group)
	if err != nil {
		return nil, err
	}
	out := make([]cfgov.ServiceInstance, 0, len(items))
	for _, item := range items {
		out = append(out, cfgov.ServiceInstance{
			IP:       item.IP,
			Port:     item.Port,
			Healthy:  item.Healthy,
			Enabled:  item.Enabled,
			Weight:   item.Weight,
			Metadata: item.Metadata,
		})
	}
	return out, nil
}

func (b *Backend) RegisterInstance(ctx context.Context, service, ip string, port int, opts cfgov.InstanceOptions) error {
	return b.client.RegisterInstance(ctx, service, ip, port, apiInstanceOptions(opts))
}

func (b *Backend) DeregisterInstance(ctx context.Context, service, ip string, port int, opts cfgov.InstanceOptions) error {
	return b.client.DeregisterInstance(ctx, service, ip, port, apiInstanceOptions(opts))
}

func apiInstanceOptions(opts cfgov.InstanceOptions) api.InstanceOptions {
	return api.InstanceOptions{
		GroupName: opts.GroupName,
		Cluster:   opts.Cluster,
		Weight:    opts.Weight,
		Healthy:   opts.Healthy,
		Enabled:   opts.Enabled,
		Ephemeral: opts.Ephemeral,
		Metadata:  opts.Metadata,
	}
}

func (b *Backend) requireNamespace(namespace string) error {
	current := b.client.Namespace()
	if namespace == "" || namespace == current {
		return nil
	}
	return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("backend namespace %q does not match client namespace %q", namespace, current), nil)
}

func (b *Backend) checkCAS(ctx context.Context, coord cfgov.Coordinate, expected string) error {
	if expected == "" {
		return nil
	}
	current, err := b.CurrentRevision(ctx, coord)
	if err != nil {
		return err
	}
	if current != expected {
		return apperrors.New(apperrors.CodeConflict, "config revision changed", nil)
	}
	return nil
}

func md5Hex(content []byte) string {
	sum := md5.Sum(content) // #nosec G401 -- Nacos revision compatibility fingerprint, not cryptography.
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
