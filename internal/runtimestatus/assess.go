package runtimestatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Derived process and role states.
const (
	Running       = "running"        // heartbeat within StaleAfter
	Stale         = "stale"          // heartbeat older than StaleAfter, newer than OfflineAfter: may be hung or overloaded
	Offline       = "offline"        // stopped gracefully, heartbeat older than OfflineAfter, or expected but never reported
	NotConfigured = "not_configured" // the role is not part of this installation's configuration and nothing reports it
	Unknown       = "unknown"        // the records could not be read
)

// Heartbeat multipliers: a process is stale after missing 3 heartbeats and
// offline after missing 12.
const (
	staleBeats   = 3
	offlineBeats = 12
	maxRecords   = 256 // bound the directory scan
	maxRecordLen = 64 << 10
)

// Process is one process instance as assessed now.
type Process struct {
	Record
	Assessed   string  `json:"assessed_state"`
	Reason     string  `json:"reason"`
	AgeSeconds float64 `json:"age_seconds"`
	// Current is true for every instance that is running now, and for the
	// instance a role reports when none of that role's instances runs.
	// Other instances (a stopped or killed earlier run) are history: listed
	// with their own state, never merged.
	Current bool `json:"current"`
}

// RoleStatus is one role's state for the installation.
type RoleStatus struct {
	Role       string     `json:"role"`
	Expected   bool       `json:"expected"`
	State      string     `json:"state"`
	Reason     string     `json:"reason"`
	InstanceID string     `json:"instance_id,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
}

// Rejected is a record that was not combined, with why.
type Rejected struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// View is the assessed runtime picture of one installation.
type View struct {
	ReadAt    time.Time    `json:"read_at"`
	Roles     []RoleStatus `json:"roles"`
	Processes []Process    `json:"processes"`
	Rejected  []Rejected   `json:"rejected,omitempty"`
	// Err is set when the runtime directory could not be read: every role is
	// then Unknown, never offline and never running.
	Err string `json:"error,omitempty"`
}

// Reader assesses records and remembers the newest sequence seen per
// instance, so a later read never shows an older snapshot than an earlier
// one did (e.g. a reader that raced a writer's rename).
type Reader struct {
	mu   sync.Mutex
	seen map[string]Record
}

// NewReader returns a Reader.
func NewReader() *Reader { return &Reader{seen: map[string]Record{}} }

// Assess reads <dataDir>/runtime and assesses every record of the
// installation identified by fingerprint. expected lists the roles this
// installation's configuration says should be running (for example the MCP
// proxy when a proxy config is set); a role that is neither expected nor
// reported is NotConfigured.
func (r *Reader) Assess(dataDir, fingerprint string, expected map[string]bool, now time.Time) View {
	now = now.UTC()
	v := View{ReadAt: now}
	dir := filepath.Join(dataDir, DirName)
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// No process of this installation has ever published: nothing runs
		// that we can see. Expected roles are offline, others not configured.
		entries = nil
	case err != nil:
		v.Err = fmt.Sprintf("runtime records unreadable: %v", err)
		v.Roles = unknownRoles(expected, v.Err)
		return v
	}
	var recs []Record
	for i, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || e.IsDir() {
			continue
		}
		if i >= maxRecords {
			v.Rejected = append(v.Rejected, Rejected{File: name, Reason: "over the record bound"})
			continue
		}
		rec, err := readRecord(filepath.Join(dir, name))
		switch {
		case err != nil:
			v.Rejected = append(v.Rejected, Rejected{File: name, Reason: err.Error()})
		case rec.Schema != SchemaVersion:
			v.Rejected = append(v.Rejected, Rejected{File: name, Reason: fmt.Sprintf("unsupported record schema %d", rec.Schema)})
		case rec.Installation.KeyFingerprint == "" || rec.Installation.KeyFingerprint != fingerprint:
			v.Rejected = append(v.Rejected, Rejected{File: name, Reason: "different installation: the evidence signing key fingerprint does not match this console's"})
		default:
			recs = append(recs, r.newest(rec))
		}
	}
	v.Processes = assessProcesses(recs, now)
	v.Roles = assessRoles(v.Processes, expected)
	return v
}

func (r *Reader) newest(rec Record) Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.seen[rec.InstanceID]; ok && prev.Sequence > rec.Sequence {
		return prev
	}
	r.seen[rec.InstanceID] = rec
	return rec
}

func readRecord(path string) (Record, error) {
	var rec Record
	f, err := os.Open(path) //nolint:gosec // G304: path is a directory entry under the installation's own runtime dir
	if err != nil {
		return rec, fmt.Errorf("unreadable record: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(&limited{r: f, n: maxRecordLen})
	if err := dec.Decode(&rec); err != nil {
		return rec, fmt.Errorf("malformed record: %w", err)
	}
	if rec.InstanceID == "" {
		return rec, errors.New("malformed record: no instance id")
	}
	return rec, nil
}

type limited struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (l *limited) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("record exceeds the size bound")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

func assessProcesses(recs []Record, now time.Time) []Process {
	out := make([]Process, 0, len(recs))
	for i := range recs {
		rec := &recs[i]
		p := Process{Record: *rec}
		beat := time.Duration(rec.IntervalSeconds) * time.Second
		if beat <= 0 {
			beat = DefaultInterval
		}
		age := now.Sub(rec.WrittenAt)
		if age < 0 {
			age = 0
		}
		p.AgeSeconds = age.Seconds()
		switch {
		case rec.State == StateStopped:
			p.Assessed, p.Reason = Offline, "stopped: the process recorded a graceful shutdown"
		case age <= staleBeats*beat:
			p.Assessed, p.Reason = Running, fmt.Sprintf("heartbeat %s ago (every %s)", round(age), beat)
		case age <= offlineBeats*beat:
			p.Assessed, p.Reason = Stale, fmt.Sprintf("no heartbeat for %s (expected every %s): hung, overloaded or killed", round(age), beat)
		default:
			p.Assessed, p.Reason = Offline, fmt.Sprintf("no heartbeat for %s: the process is not running or cannot write its status", round(age))
		}
		out = append(out, p)
	}
	// Most relevant first: running before stale before offline, newest
	// first within a state. A role reports its first instance in this order,
	// so a newer instance that stopped never hides an older one that still
	// serves (#554 review).
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := stateRank(out[i].Assessed), stateRank(out[j].Assessed); ri != rj {
			return ri < rj
		}
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.After(out[j].StartedAt)
		}
		return out[i].InstanceID < out[j].InstanceID
	})
	claimed := map[string]bool{}
	for i := range out {
		if out[i].Assessed == Running {
			out[i].Current = true
		}
		for _, role := range out[i].Roles {
			if !claimed[role] {
				claimed[role] = true
				out[i].Current = true
			}
		}
	}
	return out
}

func assessRoles(procs []Process, expected map[string]bool) []RoleStatus {
	roles := map[string]bool{RoleMCPProxy: true, RoleGateway: true}
	for r := range expected {
		roles[r] = true
	}
	for i := range procs {
		for _, r := range procs[i].Roles {
			roles[r] = true
		}
	}
	names := make([]string, 0, len(roles))
	for r := range roles {
		names = append(names, r)
	}
	sort.Strings(names)
	var out []RoleStatus
	for _, role := range names {
		rs := RoleStatus{Role: role, Expected: expected[role]}
		// procs is ordered most relevant first (assessProcesses).
		var cur *Process
		for i := range procs {
			if hasRole(procs[i].Roles, role) {
				cur = &procs[i]
				break
			}
		}
		switch {
		case cur != nil:
			rs.State, rs.Reason, rs.InstanceID = cur.Assessed, cur.Reason, cur.InstanceID
			t := cur.WrittenAt
			rs.LastSeen = &t
		case rs.Expected:
			rs.State, rs.Reason = Offline, "configured for this installation, but no process has reported this role"
		default:
			rs.State, rs.Reason = NotConfigured, "not part of this installation's configuration, and no process reports it"
		}
		if role == RoleNative && cur == nil && !rs.Expected {
			continue // only shown when something serves it
		}
		out = append(out, rs)
	}
	return out
}

// stateRank orders assessed states by how much they say about a role now.
func stateRank(state string) int {
	switch state {
	case Running:
		return 0
	case Stale:
		return 1
	default:
		return 2
	}
}

func unknownRoles(expected map[string]bool, reason string) []RoleStatus {
	out := []RoleStatus{{Role: RoleGateway, Expected: expected[RoleGateway], State: Unknown, Reason: reason}, {Role: RoleMCPProxy, Expected: expected[RoleMCPProxy], State: Unknown, Reason: reason}}
	return out
}

func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func round(d time.Duration) time.Duration {
	if d < time.Minute {
		return d.Round(time.Second)
	}
	return d.Round(time.Minute)
}
