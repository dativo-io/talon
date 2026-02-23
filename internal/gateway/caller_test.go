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

// TestResolveCaller_AnonymousAllowed_NonMatchingKey ensures that when require_caller_id is false,
// a request with a non-matching API key is treated as anonymous (not ErrCallerNotFound).
func TestResolveCaller_AnonymousAllowed_NonMatchingKey(t *testing.T) {
	cfg := &GatewayConfig{
		Callers: []CallerConfig{
			{Name: "known", APIKey: "talon-gw-known", TenantID: "default"},
		},
		DefaultPolicy: DefaultPolicyConfig{RequireCallerID: boolPtr(false)},
	}
	r := httptestNewRequest(context.Background(), "Bearer wrong-or-missing-key")
	caller, err := cfg.ResolveCaller(r)
	if err != nil {
		t.Fatalf("err = %v, want nil (anonymous allowed when no matching caller)", err)
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

// requestWithRemoteAddr returns a request with the given RemoteAddr (e.g. "192.168.1.1:12345").
func requestWithRemoteAddr(ctx context.Context, remoteAddr string, headers map[string]string) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, "POST", "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestClientIPFromRequest_IgnoresXFFWhenNoTrustedProxy ensures X-Forwarded-For is not trusted when TrustedProxyCIDRs is empty, preventing spoofing.
func TestClientIPFromRequest_IgnoresXFFWhenNoTrustedProxy(t *testing.T) {
	cfg := &GatewayConfig{TrustedProxyCIDRs: nil}
	r := requestWithRemoteAddr(context.Background(), "192.168.1.1:45678", map[string]string{"X-Forwarded-For": "10.1.1.1"})
	got := cfg.clientIPFromRequest(r)
	if got == nil || got.String() != "192.168.1.1" {
		t.Errorf("clientIPFromRequest = %v, want 192.168.1.1 (X-Forwarded-For must be ignored when no trusted proxy)", got)
	}
}

// TestClientIPFromRequest_UsesXFFWhenDirectPeerIsTrustedProxy ensures X-Forwarded-For is used when the direct peer is in TrustedProxyCIDRs.
func TestClientIPFromRequest_UsesXFFWhenDirectPeerIsTrustedProxy(t *testing.T) {
	cfg := &GatewayConfig{TrustedProxyCIDRs: []string{"127.0.0.0/8"}}
	r := requestWithRemoteAddr(context.Background(), "127.0.0.1:8080", map[string]string{"X-Forwarded-For": "10.1.1.1"})
	got := cfg.clientIPFromRequest(r)
	if got == nil || got.String() != "10.1.1.1" {
		t.Errorf("clientIPFromRequest = %v, want 10.1.1.1 (X-Forwarded-For used when peer is trusted proxy)", got)
	}
}

// TestClientIPFromRequest_RemoteAddrOnlyWhenPeerNotTrusted ensures that when peer is not in TrustedProxyCIDRs we use RemoteAddr even if XFF is set.
func TestClientIPFromRequest_RemoteAddrOnlyWhenPeerNotTrusted(t *testing.T) {
	cfg := &GatewayConfig{TrustedProxyCIDRs: []string{"10.0.0.0/8"}} // only 10.x is trusted
	r := requestWithRemoteAddr(context.Background(), "192.168.1.1:12345", map[string]string{"X-Forwarded-For": "10.1.1.1"})
	got := cfg.clientIPFromRequest(r)
	if got == nil || got.String() != "192.168.1.1" {
		t.Errorf("clientIPFromRequest = %v, want 192.168.1.1 (peer 192.168.1.1 is not in trusted proxy CIDRs)", got)
	}
}

// TestResolveCaller_BySourceIP_NoSpoofing ensures a client cannot impersonate an allowed IP by sending X-Forwarded-For when gateway has no trusted proxy.
func TestResolveCaller_BySourceIP_NoSpoofing(t *testing.T) {
	cfg := &GatewayConfig{
		Callers: []CallerConfig{
			{
				Name:           "engineering",
				IdentifyBy:     "source_ip",
				SourceIPRanges: []string{"10.1.1.0/24"},
				TenantID:       "default",
			},
		},
		DefaultPolicy:     DefaultPolicyConfig{RequireCallerID: boolPtr(true)},
		TrustedProxyCIDRs: nil, // no trusted proxy — X-Forwarded-For must be ignored
	}
	// Attacker at 192.168.1.1 sends X-Forwarded-For: 10.1.1.1 to try to match engineering's range.
	r := requestWithRemoteAddr(context.Background(), "192.168.1.1:12345", map[string]string{"X-Forwarded-For": "10.1.1.1"})
	caller, err := cfg.ResolveCaller(r)
	if err != ErrCallerNotFound && err != ErrCallerIDRequired {
		t.Fatalf("err = %v", err)
	}
	if caller != nil && caller.Name == "engineering" {
		t.Error("caller must not be resolved as engineering when X-Forwarded-For is spoofed and no trusted proxy")
	}
}

// TestResolveCaller_BySourceIP_TrustedProxy uses X-Forwarded-For when direct peer is in TrustedProxyCIDRs.
func TestResolveCaller_BySourceIP_TrustedProxy(t *testing.T) {
	cfg := &GatewayConfig{
		Callers: []CallerConfig{
			{
				Name:           "engineering",
				IdentifyBy:     "source_ip",
				SourceIPRanges: []string{"10.1.1.0/24"},
				TenantID:       "default",
			},
		},
		DefaultPolicy:     DefaultPolicyConfig{RequireCallerID: boolPtr(true)},
		TrustedProxyCIDRs: []string{"127.0.0.0/8"},
	}
	// Request from proxy 127.0.0.1 with real client 10.1.1.1 in X-Forwarded-For.
	r := requestWithRemoteAddr(context.Background(), "127.0.0.1:8080", map[string]string{"X-Forwarded-For": "10.1.1.1"})
	caller, err := cfg.ResolveCaller(r)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if caller == nil || caller.Name != "engineering" {
		t.Errorf("caller = %+v, want Name=engineering", caller)
	}
}

func TestPeerIPFromAddr(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.1:12345", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"invalid", ""},
	}
	for _, tt := range tests {
		got := peerIPFromAddr(tt.addr)
		if tt.want == "" {
			if got != nil {
				t.Errorf("peerIPFromAddr(%q) = %v, want nil", tt.addr, got)
			}
			continue
		}
		if got == nil || got.String() != tt.want {
			t.Errorf("peerIPFromAddr(%q) = %v, want %s", tt.addr, got, tt.want)
		}
	}
}
