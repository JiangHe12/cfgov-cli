package cfgov

import "testing"

func TestParseNacosKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		key     string
		group   string
		dataID  string
		wantErr bool
	}{
		{key: "app.yaml", group: DefaultGroup, dataID: "app.yaml"},
		{key: "OPS/app.yaml", group: "OPS", dataID: "app.yaml"},
		{key: "OPS/", wantErr: true},
		{key: "", wantErr: true},
		{key: "bad\nkey", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()
			got, err := ParseNacosKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Group != tt.group || got.DataID != tt.dataID {
				t.Fatalf("key = %#v, want group=%q dataID=%q", got, tt.group, tt.dataID)
			}
		})
	}
}
