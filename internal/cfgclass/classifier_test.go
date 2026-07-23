package cfgclass

import (
	"testing"

	"github.com/JiangHe12/opskit-core/v2/safety"
)

func TestClassifyPushStructuredPayloads(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		content     []byte
		contentType string
		want        safety.Risk
	}{
		{name: "json", content: []byte(`{"enabled":true}`), contentType: "json", want: safety.R1},
		{name: "yaml", content: []byte("enabled: true\n"), contentType: "yaml", want: safety.R1},
		{name: "yaml documents", content: []byte("enabled: true\n---\nname: cfgov\n"), contentType: "yaml", want: safety.R1},
		{name: "yaml invalid later document fails closed", content: []byte("enabled: true\n---\nname: [\n"), contentType: "yaml", want: safety.R3},
		{name: "xml", content: []byte(`<config><enabled>true</enabled></config>`), contentType: "xml", want: safety.R1},
		{name: "bad xml fail closed", content: []byte(`<config>`), contentType: "xml", want: safety.R3},
		{name: "multiple xml roots fail closed", content: []byte(`<a/><b/>`), contentType: "xml", want: safety.R3},
		{name: "bad json fail closed", content: []byte(`{"enabled":`), contentType: "json", want: safety.R3},
		{name: "unknown type fail closed", content: []byte("x"), contentType: "hocon", want: safety.R3},
		{name: "empty elevated", content: nil, contentType: "text", want: safety.R2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(OperationPush, tt.content, tt.contentType)
			if got.Risk != tt.want {
				t.Fatalf("risk = %v, want %v", got.Risk, tt.want)
			}
		})
	}
}

func TestClassifyDeleteIsR2(t *testing.T) {
	t.Parallel()
	got := Classify(OperationDelete, nil, "")
	if got.Risk != safety.R2 {
		t.Fatalf("risk = %v, want R2", got.Risk)
	}
}

func TestValidateStructuredChecksEveryYAMLDocument(t *testing.T) {
	t.Parallel()
	if err := ValidateStructured([]byte("enabled: true\n---\nname: cfgov\n"), "yaml"); err != nil {
		t.Fatalf("valid multi-document YAML rejected: %v", err)
	}
	if err := ValidateStructured([]byte("enabled: true\n---\nname: [\n"), "yaml"); err == nil {
		t.Fatal("invalid later YAML document accepted")
	}
}
