package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/printer"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestOperationTargetStripsServerUserInfo(t *testing.T) {
	target := operationTargetFromContext(&cliFlags{Server: "http://nacos:secret@127.0.0.1:8848", Context: "dev"}, cfgovctx.Context{Backend: "nacos", Namespace: "public"})
	if target.Server != "http://127.0.0.1:8848" {
		t.Fatalf("server = %q, want sanitized URL", target.Server)
	}
	if strings.Contains(target.Server, "secret") || strings.Contains(target.Server, "nacos@") {
		t.Fatalf("target leaked URL userinfo: %+v", target)
	}
}

func TestPrintOperationTargetTableHeader(t *testing.T) {
	var out bytes.Buffer
	p := printer.NewWithWriters(printer.FormatTable, &out, &bytes.Buffer{})
	target := operationTarget{Context: "dev", Backend: "nacos", Server: "http://127.0.0.1:8848", Namespace: "public"}

	printOperationTarget(p, target, operationTargetWrite)

	want := "WRITE TARGET\tcontext=dev | backend=nacos | server=http://127.0.0.1:8848 | namespace=public\n\n"
	if got := out.String(); got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestTargetDataForJSONOutput(t *testing.T) {
	target := operationTarget{Context: "dev", Backend: "nacos", Server: "http://127.0.0.1:8848", Namespace: "public"}
	payload := targetDataForOutput(&cliFlags{Output: "json"}, map[string]string{"key": "app.yaml"}, target)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded struct {
		Key    string          `json:"key"`
		Target operationTarget `json:"target"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v; output = %s", err, data)
	}
	if decoded.Key != "app.yaml" || decoded.Target != target {
		t.Fatalf("decoded = %+v", decoded)
	}
}
