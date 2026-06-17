package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/JiangHe12/opskit-core/apperrors"
)

const (
	serviceListPath = "/nacos/v1/ns/service/list"
	servicePath     = "/nacos/v1/ns/service"
	instancePath    = "/nacos/v1/ns/instance"
	instancesPath   = "/nacos/v1/ns/instance/list"
)

type ServiceListResult struct {
	Count int      `json:"count"`
	Doms  []string `json:"doms"`
}

type ServiceInstance struct {
	IP       string            `json:"ip"`
	Port     int               `json:"port"`
	Healthy  bool              `json:"healthy"`
	Enabled  bool              `json:"enabled"`
	Weight   float64           `json:"weight"`
	Metadata map[string]string `json:"metadata"`
}

func (c *Client) ListServices(ctx context.Context, page, pageSize int) (*ServiceListResult, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	params := url.Values{}
	params.Set("pageNo", strconv.Itoa(page))
	params.Set("pageSize", strconv.Itoa(pageSize))
	if c.namespace != "" {
		params.Set("namespaceId", c.namespace)
	}
	body, err := c.get(ctx, serviceListPath, params)
	if err != nil {
		return nil, err
	}
	var result ServiceListResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, apperrors.New(apperrors.CodeBackendError, "parse services", err)
	}
	return &result, nil
}

func (c *Client) GetService(ctx context.Context, serviceName string) (map[string]any, error) {
	params := url.Values{}
	params.Set("serviceName", serviceName)
	if c.namespace != "" {
		params.Set("namespaceId", c.namespace)
	}
	body, err := c.get(ctx, servicePath, params)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, apperrors.New(apperrors.CodeBackendError, "parse service", err)
	}
	return result, nil
}

func (c *Client) ListInstances(ctx context.Context, serviceName, groupName string) ([]ServiceInstance, error) {
	params := url.Values{}
	params.Set("serviceName", serviceName)
	if groupName != "" {
		params.Set("groupName", groupName)
	}
	if c.namespace != "" {
		params.Set("namespaceId", c.namespace)
	}
	body, err := c.get(ctx, instancesPath, params)
	if err != nil {
		return nil, err
	}
	var result struct {
		Hosts []ServiceInstance `json:"hosts"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, apperrors.New(apperrors.CodeBackendError, "parse instances", err)
	}
	return result.Hosts, nil
}

// InstanceOptions carries the optional parameters Nacos accepts on
// instance register/deregister. Zero/empty values are not sent so the
// Nacos server defaults apply (groupName=DEFAULT_GROUP, cluster=DEFAULT,
// weight=1.0, ephemeral=true). Callers SHOULD set Ephemeral=false for CLI
// registrations: ephemeral instances rely on a heartbeat the CLI does not
// send, so they are removed by the server within ~15 seconds otherwise.
type InstanceOptions struct {
	GroupName string
	Cluster   string
	Weight    float64
	Healthy   *bool
	Enabled   *bool
	Ephemeral *bool
	Metadata  map[string]string
}

func (c *Client) RegisterInstance(ctx context.Context, serviceName, ip string, port int, opts InstanceOptions) error {
	params, err := serviceInstanceParams(serviceName, ip, port, opts)
	if err != nil {
		return err
	}
	if c.namespace != "" {
		params.Set("namespaceId", c.namespace)
	}
	body, err := c.post(ctx, instancePath, params)
	if err != nil {
		return err
	}
	if string(body) != "ok" && string(body) != "true" {
		return unexpectedMutationResponse("register instance", body)
	}
	return nil
}

func (c *Client) DeregisterInstance(ctx context.Context, serviceName, ip string, port int, opts InstanceOptions) error {
	params, err := serviceInstanceParams(serviceName, ip, port, opts)
	if err != nil {
		return err
	}
	if c.namespace != "" {
		params.Set("namespaceId", c.namespace)
	}
	body, err := c.deleteIdempotent(ctx, instancePath, params)
	if err != nil {
		return err
	}
	if string(body) != "ok" && string(body) != "true" {
		return unexpectedMutationResponse("deregister instance", body)
	}
	return nil
}

// InstanceAction dispatches to RegisterInstance or DeregisterInstance based on kind.
func (c *Client) InstanceAction(ctx context.Context, kind, serviceName, ip string, port int, opts InstanceOptions) error {
	if kind == "deregister" {
		return c.DeregisterInstance(ctx, serviceName, ip, port, opts)
	}
	return c.RegisterInstance(ctx, serviceName, ip, port, opts)
}

func serviceInstanceParams(serviceName, ip string, port int, opts InstanceOptions) (url.Values, error) {
	params := url.Values{}
	params.Set("serviceName", serviceName)
	params.Set("ip", ip)
	params.Set("port", strconv.Itoa(port))
	if opts.GroupName != "" {
		params.Set("groupName", opts.GroupName)
	}
	if opts.Cluster != "" {
		params.Set("clusterName", opts.Cluster)
	}
	if opts.Weight > 0 {
		params.Set("weight", strconv.FormatFloat(opts.Weight, 'f', -1, 64))
	}
	if opts.Healthy != nil {
		params.Set("healthy", strconv.FormatBool(*opts.Healthy))
	}
	if opts.Enabled != nil {
		params.Set("enabled", strconv.FormatBool(*opts.Enabled))
	}
	if opts.Ephemeral != nil {
		params.Set("ephemeral", strconv.FormatBool(*opts.Ephemeral))
	}
	if len(opts.Metadata) > 0 {
		// Nacos accepts metadata as a single JSON-encoded query parameter.
		buf, err := json.Marshal(opts.Metadata)
		if err != nil {
			return params, fmt.Errorf("marshal instance metadata: %w", err)
		}
		params.Set("metadata", string(buf))
	}
	return params, nil
}
