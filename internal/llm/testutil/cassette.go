// Package testutil provides shared test utilities for the LLM layer, including
// cassette (go-vcr) support for recording and replaying HTTP interactions in provider tests.
package testutil

import (
	"net/http"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

// NewCassetteClient creates an HTTP client that records or replays interactions
// using a go-vcr cassette. Use with provider.WithHTTPClient() for deterministic
// provider tests without hitting real APIs.
//
// Example:
//
//	r, err := testutil.NewCassetteClient(t, "fixtures/openai_generate")
//	if err != nil { t.Fatal(err) }
//	defer r.Stop()
//	prov := openaiProvider.WithHTTPClient(r.GetDefaultClient())
func NewCassetteClient(t *testing.T, cassettePath string) (*recorder.Recorder, error) {
	t.Helper()
	// ModeReplayOnly: use existing cassette; fail if missing. Use ModeRecordOnce to create.
	mode := recorder.ModeReplayOnly
	r, err := recorder.NewWithOptions(&recorder.Options{
		CassetteName: cassettePath,
		Mode:         mode,
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// HTTPClientFromRecorder returns an *http.Client that uses the recorder's transport.
// Convenience when you already have a recorder and need a client for WithHTTPClient.
func HTTPClientFromRecorder(r *recorder.Recorder) *http.Client {
	return r.GetDefaultClient()
}
