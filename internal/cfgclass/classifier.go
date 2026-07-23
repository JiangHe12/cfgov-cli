package cfgclass

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/safety"
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
		if err := ValidateStructured(content, contentType); err != nil {
			return Result{Risk: safety.R3, Reason: "invalid json config payload"}
		}
		return Result{Risk: safety.R1, Reason: "structured json config write"}
	case "yaml", "yml":
		if err := ValidateStructured(content, contentType); err != nil {
			return Result{Risk: safety.R3, Reason: "invalid yaml config payload"}
		}
		return Result{Risk: safety.R1, Reason: "structured yaml config write"}
	case "xml":
		if err := ValidateStructured(content, contentType); err != nil {
			return Result{Risk: safety.R3, Reason: "invalid xml config payload"}
		}
		return Result{Risk: safety.R1, Reason: "structured xml config write"}
	default:
		return Result{Risk: safety.R3, Reason: "unknown config content type"}
	}
}

// ValidateStructured validates every document in a supported structured config
// payload. Callers wrap the returned parse error in their public error contract.
func ValidateStructured(content []byte, contentType string) error {
	switch strings.ToLower(strings.TrimSpace(contentType)) {
	case "json":
		var value any
		return json.Unmarshal(content, &value)
	case "yaml", "yml":
		decoder := yaml.NewDecoder(bytes.NewReader(content))
		for {
			var value any
			err := decoder.Decode(&value)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	case "xml":
		return validateXML(content)
	default:
		return fmt.Errorf("unsupported structured config type %q", contentType)
	}
}

func validateXML(content []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	seenRoot := false
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				if seenRoot {
					return errors.New("XML payload contains multiple root elements")
				}
				seenRoot = true
			}
			depth++
		case xml.EndElement:
			if depth == 0 {
				return errors.New("XML payload contains an unmatched end element")
			}
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return errors.New("XML payload contains text outside the root element")
			}
		}
	}
	if !seenRoot || depth != 0 {
		return errors.New("XML payload must contain exactly one complete root element")
	}
	return nil
}
