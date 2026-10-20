// Command protectedservice is the deterministic external action target used
// by the real-OpenShell live smoke (scripts/openshell-live.sh, #457/#482
// action cases). It is the consequential-effect boundary of the composition:
// it counts exactly what reached it per route (ticket reads, refunds,
// customer deletions), records the Idempotency-Key and body bytes, and
// answers fixed responses, so the harness can prove ALLOW = one dispatch,
// DENY / pending approval = zero dispatch, approved claim = exactly one
// effect, exact replay = no second effect, and that a sandbox cannot reach
// it except through Talon (OpenShell network policy). No credential, no
// real side effect.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type record struct {
	Seq            int    `json:"seq"`
	Route          string `json:"route"`
	Method         string `json:"method"`
	IdempotencyKey string `json:"idempotency_key"`
	OperationRef   string `json:"operation_ref"`
	Body           string `json:"body"`
	ReceivedAt     string `json:"received_at"`
}

type state struct {
	mu      sync.Mutex
	counts  map[string]int
	records []record
}

type view struct {
	Tickets   int      `json:"tickets"`
	Refunds   int      `json:"refunds"`
	Customers int      `json:"customers"`
	Records   []record `json:"records"`
}

func newState() *state { return &state{counts: map[string]int{}} }

// record appends one call under the lock and returns a snapshot taken in
// the same critical section (count and record list never disagree).
func (s *state) record(route string, r *http.Request, body []byte) (record, view) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[route]++
	rec := record{
		Seq: len(s.records) + 1, Route: route, Method: r.Method, IdempotencyKey: r.Header.Get("Idempotency-Key"),
		OperationRef: r.Header.Get("X-Talon-Operation-Ref"), Body: string(body), ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	s.records = append(s.records, rec)
	return rec, s.viewLocked()
}

func (s *state) viewLocked() view {
	return view{Tickets: s.counts["tickets"], Refunds: s.counts["refunds"], Customers: s.counts["customers"], Records: append([]record(nil), s.records...)}
}

func (s *state) snapshot() view {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked()
}

func (v view) json() []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// newHandler builds the service: three action routes with fixed answers
// and the harness's state route. stateFile, when set, is rewritten after
// every call with that call's snapshot.
func newHandler(st *state, stateFile string, maxBody int64) http.Handler {
	var fileMu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/__state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(st.snapshot().json())
	})
	route := func(path, name string, status int, answer string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
			if err != nil || int64(len(body)) > maxBody {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			rec, snap := st.record(name, r, body)
			if stateFile != "" {
				fileMu.Lock()
				_ = os.WriteFile(stateFile, snap.json(), 0o600) //nolint:gosec // operator-provided --state-file path of the test harness
				fileMu.Unlock()
			}
			log.Printf("%s call %d: %s body=%d bytes idempotency_key=%q", name, rec.Seq, rec.Method, len(body), rec.IdempotencyKey)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, answer, rec.Seq)
		})
	}
	route("/tickets", "tickets", http.StatusOK, `{"ticket_id":"T-1842","status":"open","read":%d}`)
	route("/refunds", "refunds", http.StatusCreated, `{"refund_id":"rf_%04d"}`)
	route("/customers", "customers", http.StatusOK, `{"deleted":%d}`)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "protected service: unknown route "+r.URL.Path, http.StatusNotFound)
	})
	return mux
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18091", "address to serve on")
	stateFile := flag.String("state-file", "", "optional path rewritten with the JSON state after every call")
	maxBody := flag.Int64("max-body", 1<<20, "maximum accepted request body in bytes")
	flag.Parse()
	srv := &http.Server{Addr: *listen, Handler: newHandler(newState(), *stateFile, *maxBody), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("protected service listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
