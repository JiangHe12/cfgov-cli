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
)

type Backend struct {
	client *api.Client
	server string
}

func New(client *api.Client, server string) *Backend {
	return &Backend{client: client, server: strings.TrimRight(server, "/")}
}

var _ cfgov.Backend = (*Backend)(nil)

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
		paged, err := b.client.ListConfigs(ctx, opts.Group, opts.Prefix, page, pageSize)
		if err != nil {
			return nil, err
		}
		return listItems(opts.Namespace, paged.PageItems), nil
	}
	list, _, err := b.client.ListConfigsAll(ctx, opts.Group, opts.Prefix, 50, limit)
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
		ResourceTypes:    []string{"config"},
		Verbs:            []string{"get", "list", "diff", "validate", "pull", "history", "listen", "push", "delete"},
		SupportsCAS:      true,
		SupportsRevision: true,
		SupportsHistory:  true,
		SupportsWatch:    true,
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
