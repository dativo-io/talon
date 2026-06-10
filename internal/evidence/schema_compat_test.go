package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEvidenceSchemaBackwardCompatible(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "pre_quickstart_record.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var ev Evidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if ev.UpstreamAuthMode != "" {
		t.Fatalf("expected empty upstream_auth_mode for legacy record, got %q", ev.UpstreamAuthMode)
	}
	if ev.UpstreamKeySource != "" {
		t.Fatalf("expected empty upstream_key_source for legacy record, got %q", ev.UpstreamKeySource)
	}
	if ev.UpstreamKeyFingerprint != "" {
		t.Fatalf("expected empty upstream_key_fingerprint for legacy record, got %q", ev.UpstreamKeyFingerprint)
	}
	if len(ev.GatewayAnnotations) != 0 {
		t.Fatalf("expected no gateway_annotations for legacy record, got %v", ev.GatewayAnnotations)
	}
	if ev.DataFlow != nil {
		t.Fatalf("expected nil data_flow for legacy record, got %+v", ev.DataFlow)
	}
}
