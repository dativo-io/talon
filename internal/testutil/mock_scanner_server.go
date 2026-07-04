package testutil

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier/presidio"
)

// ScannerAnalyzeFunc maps the text of an /analyze request to the recognizer
// results the mock engine returns.
type ScannerAnalyzeFunc func(text string) []presidio.RecognizerResult

// NewPresidioMockServer starts an httptest server speaking the Presidio
// analyzer wire format: POST /analyze returning a recognizer-result array and
// GET /health returning 200. Closed automatically at test cleanup.
func NewPresidioMockServer(t *testing.T, analyze ScannerAnalyzeFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(presidioMockHandler(analyze))
	t.Cleanup(srv.Close)
	return srv
}

// NewUDSScannerServer starts the same mock engine listening on a Unix domain
// socket and returns the unix:// endpoint for it.
func NewUDSScannerServer(t *testing.T, analyze ScannerAnalyzeFunc) string {
	t.Helper()
	// t.TempDir can exceed the ~104-byte sockaddr_un limit on macOS.
	dir, err := os.MkdirTemp("", "talon-uds")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "scanner.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listening on unix socket: %v", err)
	}
	srv := httptest.NewUnstartedServer(presidioMockHandler(analyze))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return "unix://" + socketPath
}

func presidioMockHandler(analyze ScannerAnalyzeFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Presidio Analyzer service is up"))
	})
	mux.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		results := analyze(req.Text)
		if results == nil {
			results = []presidio.RecognizerResult{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	})
	return mux
}

// Failure modes for NewFailingScannerServer.
const (
	ScannerFailTimeout   = "timeout"    // sleeps past any reasonable deadline
	ScannerFailStatus    = "status"     // returns HTTP 500
	ScannerFailMalformed = "malformed"  // returns non-JSON garbage
	ScannerFailBadOffset = "bad_offset" // returns an entity with out-of-range offsets
	ScannerFailOversized = "oversized"  // returns a body larger than the adapter's read cap
)

// NewFailingScannerServer starts a mock engine whose /analyze fails in the
// given mode. /health succeeds so startup probes pass and the failure
// surfaces on the scan path.
func NewFailingScannerServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case ScannerFailTimeout:
			// Drain the body so net/http's background read can detect the
			// client disconnect and cancel r.Context(); otherwise Close()
			// blocks for the full sleep after the client gave up.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-time.After(30 * time.Second):
			}
		case ScannerFailStatus:
			http.Error(w, "internal error", http.StatusInternalServerError)
		case ScannerFailMalformed:
			_, _ = w.Write([]byte("<html>not json</html>"))
		case ScannerFailBadOffset:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"entity_type":"EMAIL_ADDRESS","start":0,"end":999999,"score":0.9}]`))
		case ScannerFailOversized:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"entity_type":"`))
			_, _ = w.Write([]byte(strings.Repeat("x", 11<<20)))
			_, _ = w.Write([]byte(`","start":0,"end":1,"score":0.9}]`))
		default:
			http.Error(w, "unknown failure mode: "+mode, http.StatusTeapot)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
