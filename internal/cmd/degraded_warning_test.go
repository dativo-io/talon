package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWarnIfDegraded_PrintsWarningWhenStatusDegraded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"degraded","evidence_ok":false,"evidence_error":"db timeout","events_backlog_drops":2}`))
	}))
	defer srv.Close()

	var out bytes.Buffer
	warnIfDegraded(context.Background(), &out, srv.URL)
	assert.Contains(t, out.String(), "warning: runtime degraded")
	assert.Contains(t, out.String(), "evidence write failures")
	assert.Contains(t, out.String(), "collector/backlog drops")
}

func TestWarnIfDegraded_SilentWhenHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","evidence_ok":true}`))
	}))
	defer srv.Close()

	var out bytes.Buffer
	warnIfDegraded(context.Background(), &out, srv.URL)
	assert.Equal(t, "", out.String())
}
