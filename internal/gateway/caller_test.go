package gateway

import (
	"context"
	"net/http"
	"testing"
)

func TestResolveCaller_ByAPIKey(t *testing.T) {
	cfg := &GatewayConfig{
		Callers: []CallerConfig{
			{Name: "test", APIKey: "talon-gw-test-123", TenantID: "default"},
		},
		DefaultPolicy: DefaultPolicyConfig{RequireCallerID: boolPtr(false)},
	}
	r := httptestNewRequest(context.Background(), "Bearer talon-gw-test-123")
	caller, err := cfg.ResolveCaller(r)
	if err != nil {
		t.Fatal(err)
	}
	if caller == nil || caller.Name != "test" {
		t.Errorf("caller = %+v", caller)
	}
}

func TestResolveCaller_NotFound(t *testing.T) {
	cfg := &GatewayConfig{
		Callers: []CallerConfig{
			{Name: "test", APIKey: "talon-gw-test-123", TenantID: "default"},
		},
		DefaultPolicy: DefaultPolicyConfig{RequireCallerID: boolPtr(true)},
	}
	r := httptestNewRequest(context.Background(), "Bearer wrong-key")
	_, err := cfg.ResolveCaller(r)
	if err != ErrCallerNotFound {
		t.Errorf("err = %v, want ErrCallerNotFound", err)
	}
}

func TestResolveCaller_MissingKey(t *testing.T) {
	cfg := &GatewayConfig{
		Callers:       []CallerConfig{},
		DefaultPolicy: DefaultPolicyConfig{RequireCallerID: boolPtr(true)},
	}
	r, _ := http.NewRequestWithContext(context.Background(), "POST", "/", nil)
	_, err := cfg.ResolveCaller(r)
	if err != ErrCallerIDRequired {
		t.Errorf("err = %v, want ErrCallerIDRequired", err)
	}
}

func TestResolveCaller_AnonymousAllowed(t *testing.T) {
	cfg := &GatewayConfig{
		Callers:       []CallerConfig{},
		DefaultPolicy: DefaultPolicyConfig{RequireCallerID: boolPtr(false)},
	}
	r, _ := http.NewRequestWithContext(context.Background(), "POST", "/", nil)
	caller, err := cfg.ResolveCaller(r)
	if err != nil {
		t.Fatalf("err = %v, want nil (anonymous allowed)", err)
	}
	if caller == nil {
		t.Fatal("caller = nil, want anonymous caller")
	}
	if caller.Name != "anonymous" || caller.TenantID != "default" {
		t.Errorf("caller = %+v, want Name=anonymous TenantID=default", caller)
	}
}

func TestExtractAPIKey(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		r := httptestNewRequest(context.Background(), "Bearer sk-abc")
		key := extractAPIKey(r)
		if key != "sk-abc" {
			t.Errorf("key = %q", key)
		}
	})
	t.Run("x-api-key", func(t *testing.T) {
		r, _ := http.NewRequestWithContext(context.Background(), "POST", "/", nil)
		r.Header.Set("x-api-key", "sk-xyz")
		key := extractAPIKey(r)
		if key != "sk-xyz" {
			t.Errorf("key = %q", key)
		}
	})
}

func httptestNewRequest(ctx context.Context, auth string) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, "POST", "/", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

func boolPtr(b bool) *bool { return &b }
