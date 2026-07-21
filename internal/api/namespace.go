package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const namespacePath = "/nacos/v1/console/namespaces"

type NamespaceItem struct {
	Namespace         string `json:"namespace"`
	NamespaceShowName string `json:"namespaceShowName"`
	NamespaceDesc     string `json:"namespaceDesc"`
	Quota             int    `json:"quota"`
	ConfigCount       int    `json:"configCount"`
	Type              int    `json:"type"`
}

func (c *Client) ListNamespaces(ctx context.Context) ([]NamespaceItem, error) {
	body, err := c.get(ctx, namespacePath, url.Values{})
	if err != nil {
		return nil, err
	}
	var result struct {
		Data []NamespaceItem `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, apperrors.New(apperrors.CodeBackendError, "parse namespaces", err)
	}
	return result.Data, nil
}

func (c *Client) CreateNamespace(ctx context.Context, id, name, desc string) error {
	params := url.Values{}
	params.Set("customNamespaceId", id)
	params.Set("namespaceName", name)
	params.Set("namespaceDesc", desc)
	body, err := c.post(ctx, namespacePath, params)
	if err != nil {
		return err
	}
	if string(body) != "true" {
		return c.namespaceMutationError(ctx, "create namespace", id, body, true)
	}
	return nil
}

func (c *Client) UpdateNamespace(ctx context.Context, id, name, desc string) error {
	params := url.Values{}
	params.Set("namespace", id)
	params.Set("namespaceShowName", name)
	params.Set("namespaceDesc", desc)
	body, err := c.putIdempotent(ctx, namespacePath, params)
	if err != nil {
		return err
	}
	if string(body) != "true" {
		return c.namespaceMutationError(ctx, "update namespace", id, body, false)
	}
	return nil
}

func (c *Client) DeleteNamespace(ctx context.Context, id string) error {
	params := url.Values{}
	params.Set("namespaceId", id)
	body, err := c.deleteIdempotent(ctx, namespacePath, params)
	if err != nil {
		return err
	}
	if string(body) != "true" {
		return c.namespaceMutationError(ctx, "delete namespace", id, body, false)
	}
	return nil
}

func (c *Client) namespaceMutationError(ctx context.Context, action, id string, body []byte, create bool) error {
	original := unexpectedMutationResponse(action, body)
	appErr := apperrors.AsAppError(original)
	if appErr.Code != apperrors.CodeServerError || strings.TrimSpace(string(body)) != "false" {
		return original
	}
	exists, err := c.namespaceExists(ctx, id)
	if err != nil {
		return original
	}
	if create && exists {
		return apperrors.New(
			apperrors.CodeResourceAlreadyExists,
			fmt.Sprintf("namespace %q already exists", id),
			nil,
		)
	}
	if !create && !exists {
		return apperrors.New(
			apperrors.CodeResourceNotFound,
			fmt.Sprintf("namespace %q not found", id),
			nil,
		)
	}
	return original
}

func (c *Client) namespaceExists(ctx context.Context, id string) (bool, error) {
	items, err := c.ListNamespaces(ctx)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.Namespace == id {
			return true, nil
		}
	}
	return false, nil
}
