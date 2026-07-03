package failover

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyHTTP(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		status        int
		wantClass     string
		wantTransient bool
	}{
		{name: "success", err: nil, status: 200, wantClass: ClassNone, wantTransient: false},
		{name: "no status yet", err: nil, status: 0, wantClass: ClassNone, wantTransient: false},
		{name: "context deadline", err: context.DeadlineExceeded, status: 0, wantClass: ClassTimeout, wantTransient: true},
		{name: "caller canceled is never transient", err: context.Canceled, status: 0, wantClass: ClassCanceled, wantTransient: false},
		{name: "net timeout", err: timeoutErr{}, status: 0, wantClass: ClassTimeout, wantTransient: true},
		{name: "connection refused", err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}, status: 0, wantClass: ClassConnection, wantTransient: true},
		{name: "generic transport error", err: errors.New("EOF"), status: 0, wantClass: ClassConnection, wantTransient: true},
		{name: "429 rate limited", err: nil, status: 429, wantClass: ClassRateLimited, wantTransient: true},
		{name: "500", err: nil, status: 500, wantClass: ClassUpstream5xx, wantTransient: true},
		{name: "502", err: nil, status: 502, wantClass: ClassUpstream5xx, wantTransient: true},
		{name: "503", err: nil, status: 503, wantClass: ClassUpstream5xx, wantTransient: true},
		{name: "504", err: nil, status: 504, wantClass: ClassUpstream5xx, wantTransient: true},
		{name: "401 auth is permanent", err: nil, status: 401, wantClass: ClassAuth, wantTransient: false},
		{name: "403 auth is permanent", err: nil, status: 403, wantClass: ClassAuth, wantTransient: false},
		{name: "404 client error is permanent", err: nil, status: 404, wantClass: ClassClient, wantTransient: false},
		{name: "422 client error is permanent", err: nil, status: 422, wantClass: ClassClient, wantTransient: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyHTTP(tt.err, tt.status)
			assert.Equal(t, tt.wantClass, got.Class)
			assert.Equal(t, tt.wantTransient, got.Transient)
		})
	}
}

func TestClassifyProviderCode(t *testing.T) {
	tests := []struct {
		code          string
		wantClass     string
		wantTransient bool
	}{
		{code: "rate_limit", wantClass: ClassRateLimited, wantTransient: true},
		{code: "server_error", wantClass: ClassUpstream5xx, wantTransient: true},
		{code: "timeout", wantClass: ClassTimeout, wantTransient: true},
		{code: "auth_failed", wantClass: ClassAuth, wantTransient: false},
		{code: "model_not_found", wantClass: ClassClient, wantTransient: false},
		{code: "something_else", wantClass: ClassNone, wantTransient: false},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := ClassifyProviderCode(tt.code)
			assert.Equal(t, tt.wantClass, got.Class)
			assert.Equal(t, tt.wantTransient, got.Transient)
		})
	}
}

func TestSovereigntyFilter(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		mode    string
		region  string
		allowed bool
	}{
		{name: "eu_strict allows EU", mode: "eu_strict", region: "EU", allowed: true},
		{name: "eu_strict allows LOCAL", mode: "eu_strict", region: "LOCAL", allowed: true},
		{name: "eu_strict allows lowercase eu", mode: "eu_strict", region: "eu", allowed: true},
		{name: "eu_strict denies US", mode: "eu_strict", region: "US", allowed: false},
		{name: "eu_strict fails closed on empty region", mode: "eu_strict", region: "", allowed: false},
		{name: "eu_strict fails closed on unknown region", mode: "eu_strict", region: "unknown", allowed: false},
		{name: "eu_preferred allows US", mode: "eu_preferred", region: "US", allowed: true},
		{name: "global allows US", mode: "global", region: "US", allowed: true},
		{name: "empty mode allows US", mode: "", region: "US", allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewSovereigntyFilter(tt.mode)
			res := f.Allows(ctx, Candidate{Provider: "p", Region: tt.region})
			assert.Equal(t, tt.allowed, res.Allowed)
			if !tt.allowed {
				assert.Equal(t, "sovereignty", res.Filter)
				assert.NotEmpty(t, res.Reason)
			}
		})
	}
}

func TestPipeline_FirstRefusalWins(t *testing.T) {
	ctx := context.Background()
	p := Pipeline{NewSovereigntyFilter("eu_strict")}
	res := p.Evaluate(ctx, Candidate{Provider: "us-provider", Region: "US"})
	assert.False(t, res.Allowed)
	assert.Equal(t, "sovereignty", res.Filter)

	res = p.Evaluate(ctx, Candidate{Provider: "eu-provider", Region: "EU"})
	assert.True(t, res.Allowed)
}

// A timeout error wrapped inside a net.OpError still classifies as timeout.
func TestClassifyHTTP_WrappedTimeout(t *testing.T) {
	err := &net.OpError{Op: "read", Err: timeoutErr{}}
	got := ClassifyHTTP(err, 0)
	assert.Equal(t, ClassTimeout, got.Class)
	assert.True(t, got.Transient)
}
