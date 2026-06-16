package cfgclass

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/JiangHe12/opskit-core/safety"
	"gopkg.in/yaml.v3"
)

type Operation string

const (
	OperationPush   Operation = "push"
	OperationDelete Operation = "delete"
)

type Result struct {
	Risk   safety.Risk `json:"risk"`
	Reason string      `json:"reason"`
}

func Classify(op Operation, content []byte, contentType string) Result {
	switch op {
	case OperationDelete:
		return Result{Risk: safety.R2, Reason: "config delete is destructive"}
	case OperationPush:
		return classifyPush(content, contentType)
	default:
		return Result{Risk: safety.R3, Reason: "unknown config operation"}
	}
}

func classifyPush(content []byte, contentType string) Result {
	if len(content) == 0 {
		return Result{Risk: safety.R2, Reason: "empty config payload is elevated"}
	}
	switch strings.ToLower(strings.TrimSpace(contentType)) {
	case "", "text", "properties":
		if bytes.ContainsAny(content, "\x00") {
			return Result{Risk: safety.R3, Reason: "config payload contains NUL bytes"}
		}
		return Result{Risk: safety.R1, Reason: "text config write"}
	case "json":
		var v any
		if err := json.Unmarshal(content, &v); err != nil {
			return Result{Risk: safety.R3, Reason: "invalid json config payload"}
		}
		return Result{Risk: safety.R1, Reason: "structured json config write"}
	case "yaml", "yml":
		var v any
		dec := yaml.NewDecoder(bytes.NewReader(content))
		if err := dec.Decode(&v); err != nil {
			return Result{Risk: safety.R3, Reason: "invalid yaml config payload"}
		}
		return Result{Risk: safety.R1, Reason: "structured yaml config write"}
	default:
		return Result{Risk: safety.R3, Reason: "unknown config content type"}
	}
}
