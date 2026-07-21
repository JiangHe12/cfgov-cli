package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/printer"

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

	if err := printOperationTarget(p, target, operationTargetWrite); err != nil {
		t.Fatalf("printOperationTarget() error = %v", err)
	}

	want := "WRITE TARGET\tcontext=dev | backend=nacos | server=http://127.0.0.1:8848 | namespace=public\n\n"
	if got := out.String(); got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestPrintOperationTargetPropagatesWriteFailure(t *testing.T) {
	p := printer.NewWithWriters(printer.FormatPlain, failingOutputWriter{}, &bytes.Buffer{})
	err := printOperationTarget(p, operationTarget{Context: "dev"}, operationTargetRead)
	if err == nil {
		t.Fatal("printOperationTarget() error = nil, want output write failure")
	}
}

type failingOutputWriter struct{}

func (failingOutputWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected output failure")
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
