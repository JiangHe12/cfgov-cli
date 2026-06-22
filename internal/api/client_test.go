package api

import (
	"testing"
	"time"
)

func TestNewClientNormalizesPublicNamespaceToDefaultTenant(t *testing.T) {
	t.Parallel()
	client := NewClient("http://nacos.example", "", "", "public", time.Second)
	if got := client.Namespace(); got != "" {
		t.Fatalf("Namespace() = %q, want empty public tenant", got)
	}
}

func TestNewClientKeepsNonPublicNamespace(t *testing.T) {
	t.Parallel()
	client := NewClient("http://nacos.example", "", "", "wmc_dev", time.Second)
	if got := client.Namespace(); got != "wmc_dev" {
		t.Fatalf("Namespace() = %q, want wmc_dev", got)
	}
}

func TestWithNamespaceNormalizesPublicNamespaceToDefaultTenant(t *testing.T) {
	t.Parallel()
	client := NewClient("http://nacos.example", "", "", "wmc_dev", time.Second).WithNamespace("public")
	if got := client.Namespace(); got != "" {
		t.Fatalf("Namespace() = %q, want empty public tenant", got)
	}
}
