package rule

// FlowRule is a Sentinel flow control rule.
type FlowRule struct {
	Resource          string  `json:"resource"`
	LimitApp          string  `json:"limitApp,omitempty"`
	Grade             int     `json:"grade"`
	Count             float64 `json:"count"`
	Strategy          int     `json:"strategy,omitempty"`
	RefResource       string  `json:"refResource,omitempty"`
	ControlBehavior   int     `json:"controlBehavior,omitempty"`
	WarmUpPeriodSec   int     `json:"warmUpPeriodSec,omitempty"`
	MaxQueueingTimeMs int     `json:"maxQueueingTimeMs,omitempty"`
	ClusterMode       bool    `json:"clusterMode,omitempty"`
}

// DegradeRule is a Sentinel circuit-breaking rule.
type DegradeRule struct {
	Resource           string  `json:"resource"`
	LimitApp           string  `json:"limitApp,omitempty"`
	Grade              int     `json:"grade"`
	Count              float64 `json:"count"`
	TimeWindow         int     `json:"timeWindow"`
	MinRequestAmount   int     `json:"minRequestAmount,omitempty"`
	StatIntervalMs     int     `json:"statIntervalMs,omitempty"`
	SlowRatioThreshold float64 `json:"slowRatioThreshold,omitempty"`
}

// SystemRule is a Sentinel system adaptive protection rule.
type SystemRule struct {
	HighestSystemLoad float64 `json:"highestSystemLoad,omitempty"`
	AvgRT             int     `json:"avgRt,omitempty"`
	MaxThread         int     `json:"maxThread,omitempty"`
	QPS               float64 `json:"qps,omitempty"`
	HighestCPUUsage   float64 `json:"highestCpuUsage,omitempty"`
}

// AuthorityRule is a Sentinel authority rule.
type AuthorityRule struct {
	Resource string `json:"resource"`
	LimitApp string `json:"limitApp"`
	Strategy int    `json:"strategy"`
}

// ParamFlowItem is a special value entry for param flow rules.
type ParamFlowItem struct {
	Object string  `json:"object"`
	Count  float64 `json:"count"`
}

// ParamFlowRule is a Sentinel hotspot parameter flow rule.
type ParamFlowRule struct {
	Resource          string          `json:"resource"`
	Grade             int             `json:"grade"`
	ParamIdx          int             `json:"paramIdx"`
	Count             float64         `json:"count"`
	ControlBehavior   int             `json:"controlBehavior,omitempty"`
	MaxQueueingTimeMs int             `json:"maxQueueingTimeMs,omitempty"`
	BurstCount        int             `json:"burstCount,omitempty"`
	DurationInSec     int             `json:"durationInSec,omitempty"`
	ParamFlowItemList []ParamFlowItem `json:"paramFlowItemList,omitempty"`
}
