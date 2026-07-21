// internal/api/config.go
// Nacos 配置管理 API 封装
// 对应 /nacos/v1/cs/configs 系列接口

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const (
	configPath         = "/nacos/v1/cs/configs"
	configListenerPath = "/nacos/v1/cs/configs/listener"
)

// ConfigItem 代表一条配置
type ConfigItem struct {
	DataID  string `json:"dataId"`
	Group   string `json:"group"`
	Content string `json:"content"`
	MD5     string `json:"md5"`
	Tenant  string `json:"tenant"` // namespace
	AppName string `json:"appName"`
	Type    string `json:"type"` // yaml/properties/json/text
}

// ConfigListResult Nacos 分页返回结构
type ConfigListResult struct {
	TotalCount     int          `json:"totalCount"`
	PageNumber     int          `json:"pageNumber"`
	PagesAvailable int          `json:"pagesAvailable"`
	PageItems      []ConfigItem `json:"pageItems"`
}

// HistoryItem 配置历史条目
type HistoryItem struct {
	ID           string `json:"id"`
	LastID       string `json:"lastId"`
	DataID       string `json:"dataId"`
	Group        string `json:"group"`
	Tenant       string `json:"tenant"`
	OpType       string `json:"opType"` // I=insert U=update D=delete
	CreatedTime  string `json:"createdTime"`
	LastModified string `json:"lastModifiedTime"`
	SrcUser      string `json:"srcUser"`
}

// UnmarshalJSON handles Nacos 1.x (numeric) and 2.x (string) ID formats
// without losing precision on int64 IDs > 2^53 (json.Number keeps the
// original digit string instead of round-tripping through float64).
func (h *HistoryItem) UnmarshalJSON(data []byte) error {
	type Alias HistoryItem
	aux := &struct {
		ID     json.Number `json:"id"`
		LastID json.Number `json:"lastId"`
		*Alias
	}{Alias: (*Alias)(h)}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(aux); err != nil {
		// Fallback: some Nacos versions return id as a string, which is
		// already valid for json.Number. The decoder above accepts both.
		// If decoding genuinely fails, surface it.
		return err
	}
	h.ID = string(aux.ID)
	h.LastID = string(aux.LastID)
	return nil
}

// GetConfig 获取单条配置内容
func (c *Client) GetConfig(ctx context.Context, dataID, group string) (string, error) {
	if group == "" {
		group = "DEFAULT_GROUP"
	}
	params := url.Values{}
	params.Set("dataId", dataID)
	params.Set("group", group)
	if c.namespace != "" {
		params.Set("tenant", c.namespace)
	}

	body, err := c.get(ctx, configPath, params)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// PublishConfig 发布（新建或更新）配置
func (c *Client) PublishConfig(ctx context.Context, dataID, group, content, configType string) error {
	if group == "" {
		group = "DEFAULT_GROUP"
	}
	params := url.Values{}
	params.Set("dataId", dataID)
	params.Set("group", group)
	params.Set("content", content)
	if configType != "" {
		params.Set("type", configType)
	}
	if c.namespace != "" {
		params.Set("tenant", c.namespace)
	}

	body, err := c.postIdempotent(ctx, configPath, params)
	if err != nil {
		return err
	}
	if string(body) != "true" {
		return unexpectedMutationResponse("publish", body)
	}
	return nil
}

// DeleteConfig 删除配置
func (c *Client) DeleteConfig(ctx context.Context, dataID, group string) error {
	if group == "" {
		group = "DEFAULT_GROUP"
	}
	params := url.Values{}
	params.Set("dataId", dataID)
	params.Set("group", group)
	if c.namespace != "" {
		params.Set("tenant", c.namespace)
	}

	body, err := c.deleteIdempotent(ctx, configPath, params)
	if err != nil {
		return err
	}
	if string(body) != "true" {
		return unexpectedMutationResponse("delete", body)
	}
	return nil
}

// ListConfigs 分页列出配置，group/search 可为空
func (c *Client) ListConfigs(ctx context.Context, group, search string, page, pageSize int) (*ConfigListResult, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	params := url.Values{}
	searchMode := "blur"
	if search != "" {
		searchMode = "accurate"
	}
	params.Set("search", searchMode)
	params.Set("pageNo", fmt.Sprintf("%d", page))
	params.Set("pageSize", fmt.Sprintf("%d", pageSize))
	params.Set("dataId", search) // Nacos requires dataId; empty value means no filter.
	params.Set("group", group)   // Nacos requires group; empty value means all groups.
	if c.namespace != "" {
		params.Set("tenant", c.namespace)
	}

	body, err := c.get(ctx, configPath, params)
	if err != nil {
		return nil, err
	}

	var result ConfigListResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, apperrors.New(apperrors.CodeBackendError, "parse list result", err)
	}
	return &result, nil
}

// ListConfigsAll pages through config list results up to maxItems.
func (c *Client) ListConfigsAll(ctx context.Context, group, search string, pageSize, maxItems int) (*ConfigListResult, bool, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if maxItems <= 0 {
		maxItems = 1000
	}
	combined := &ConfigListResult{PageNumber: 1}
	truncated := false
	for page := 1; ; page++ {
		result, err := c.ListConfigs(ctx, group, search, page, pageSize)
		if err != nil {
			return nil, false, err
		}
		if page == 1 {
			combined.TotalCount = result.TotalCount
			combined.PagesAvailable = result.PagesAvailable
		}
		for _, item := range result.PageItems {
			if len(combined.PageItems) >= maxItems {
				truncated = true
				return combined, truncated, nil
			}
			combined.PageItems = append(combined.PageItems, item)
		}
		if page >= result.PagesAvailable || len(result.PageItems) == 0 {
			break
		}
	}
	if combined.TotalCount > len(combined.PageItems) {
		truncated = len(combined.PageItems) >= maxItems
	}
	return combined, truncated, nil
}

// GetHistory 获取配置变更历史
func (c *Client) GetHistory(ctx context.Context, dataID, group string, page, pageSize int) ([]HistoryItem, int, error) {
	if group == "" {
		group = "DEFAULT_GROUP"
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	params := url.Values{}
	params.Set("dataId", dataID)
	params.Set("group", group)
	params.Set("pageNo", fmt.Sprintf("%d", page))
	params.Set("pageSize", fmt.Sprintf("%d", pageSize))
	params.Set("search", "accurate")
	if c.namespace != "" {
		params.Set("tenant", c.namespace)
	}

	body, err := c.get(ctx, "/nacos/v1/cs/history", params)
	if err != nil {
		return nil, 0, err
	}

	var result struct {
		TotalCount int           `json:"totalCount"`
		PageItems  []HistoryItem `json:"pageItems"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, 0, apperrors.New(apperrors.CodeBackendError, "parse history", err)
	}
	return result.PageItems, result.TotalCount, nil
}

func (c *Client) GetHistoryConfig(ctx context.Context, dataID, group string, nid string) (string, error) {
	if group == "" {
		group = "DEFAULT_GROUP"
	}
	params := url.Values{}
	params.Set("dataId", dataID)
	params.Set("group", group)
	params.Set("nid", nid)
	if c.namespace != "" {
		params.Set("tenant", c.namespace)
	}
	body, err := c.get(ctx, "/nacos/v1/cs/history", params)
	if err != nil {
		return "", err
	}
	var result struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", apperrors.New(apperrors.CodeBackendError, "parse history content", err)
	}
	return result.Content, nil
}

func (c *Client) ListenConfig(ctx context.Context, dataID, group, md5 string, timeout time.Duration) (bool, error) {
	return c.listenConfigOnce(ctx, dataID, group, md5, timeout, true)
}

// encodeListenLine builds the Nacos Listening-Configs value. Fields are
// separated by \x02 (STX) and the line is terminated by \x01 (SOH).
func encodeListenLine(dataID, group, md5, tenant string) string {
	return fmt.Sprintf("%s\x02%s\x02%s\x02%s\x01", dataID, group, md5, tenant)
}

// listenConfigOnce performs a single long-poll listen request. retryAuth limits
// the 403→relogin→retry path to a single iteration to prevent recursive auth
// storms when permissions are revoked mid-session.
func (c *Client) listenConfigOnce(ctx context.Context, dataID, group, md5 string, timeout time.Duration, retryAuth bool) (bool, error) {
	if group == "" {
		group = "DEFAULT_GROUP"
	}
	if err := c.ensureToken(ctx); err != nil {
		return false, err
	}
	listenLine := encodeListenLine(dataID, group, md5, c.namespace)
	params := url.Values{}
	params.Set("Listening-Configs", listenLine)
	if c.namespace != "" {
		params.Set("tenant", c.namespace)
	}
	usedToken := c.currentToken()
	if usedToken != "" {
		params.Set("accessToken", usedToken)
	}
	listenCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(listenCtx, http.MethodPost, c.baseURL+configListenerPath, strings.NewReader(params.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Long-Pulling-Timeout", strconv.Itoa(int(timeout.Milliseconds())))
	// Use the pre-initialized dedicated client so the global c.httpClient.Timeout
	// (default 30s) does not abort the long-poll early. The listenCtx still
	// bounds the call.
	resp, err := c.listenClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return false, err
	}
	if resp.StatusCode == http.StatusForbidden && retryAuth && c.username != "" {
		var changed bool
		retried, err := c.handleAuthRetry(ctx, usedToken, "POST "+redactURL(configListenerPath), func() error {
			var retryErr error
			changed, retryErr = c.listenConfigOnce(ctx, dataID, group, md5, timeout, false)
			return retryErr
		})
		if retried || err != nil {
			return changed, err
		}
	}
	if resp.StatusCode >= 400 {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return false, apperrors.FromHTTP(resp.StatusCode, message)
	}
	return strings.TrimSpace(string(body)) != "", nil
}
