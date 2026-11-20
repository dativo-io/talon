package runtimestatus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProveLoaded(t *testing.T) {
	proc := func(id, state string, current bool, agents ...Agent) Process {
		return Process{Record: Record{InstanceID: id, Catalog: &Catalog{Agents: agents}}, Assessed: state, Current: current}
	}
	hr := func(d string) Agent { return Agent{Name: "hr", PolicyDigest: d} }
	cases := []struct {
		name     string
		v        View
		readable bool
		want     string
	}{
		{"records unreadable", View{}, false, LoadedUnknown},
		{"nothing reports a catalog", View{}, true, LoadedUnknown},
		{"stale process proves nothing", View{Processes: []Process{proc("a", Stale, true, hr("d1"))}}, true, LoadedUnknown},
		{"history instance proves nothing", View{Processes: []Process{proc("a", Running, false, hr("d1"))}}, true, LoadedUnknown},
		{"running without the use case", View{Processes: []Process{proc("a", Running, true, Agent{Name: "other", PolicyDigest: "x"})}}, true, NotInActiveGeneration},
		{"other tenant is not this use case", View{Processes: []Process{proc("a", Running, true, Agent{Name: "hr", TenantID: "acme", PolicyDigest: "d1"})}}, true, NotInActiveGeneration},
		{"matches", View{Processes: []Process{proc("a", Running, true, hr("d1"))}}, true, LoadedMatchesFile},
		{"differs", View{Processes: []Process{proc("a", Running, true, hr("d0"))}}, true, LoadedDiffersFromFile},
		{"processes disagree", View{Processes: []Process{proc("a", Running, true, hr("d1")), proc("b", Running, true, hr("d0"))}}, true, LoadedUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ProveLoaded(tc.v, tc.readable, "hr", "", "d1")
			assert.Equal(t, tc.want, got.State, got.Reason)
			assert.NotEmpty(t, got.Reason)
		})
	}
}

// #567 review. Which processes can have served a request at a moment, as far
// as their own records say: a recorded stop ends a process; one that still
// reports has no end; one that stopped reporting without a stop record may
// have served for as long as the assessment waits before calling it offline.
func TestProcess_CanHaveServedAt(t *testing.T) {
	start := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	rec := func(assessed string, written time.Time, stopped *time.Time) *Process {
		return &Process{Record: Record{StartedAt: start, WrittenAt: written, StoppedAt: stopped, IntervalSeconds: 5}, Assessed: assessed}
	}
	stop := start.Add(time.Hour)
	last := start.Add(30 * time.Minute)
	for _, tc := range []struct {
		name string
		p    *Process
		at   time.Time
		want bool
	}{
		{"before it started", rec(Running, last, nil), start.Add(-time.Second), false},
		{"running: no end", rec(Running, last, nil), last.Add(24 * time.Hour), true},
		{"late but not yet taken for gone: no end", rec(Stale, last, nil), last.Add(time.Hour), true},
		{"stopped: until the recorded stop", rec(Offline, stop, &stop), stop, true},
		{"stopped: not after the recorded stop", rec(Offline, stop, &stop), stop.Add(time.Second), false},
		{"killed: three seconds after its last report", rec(Offline, last, nil), last.Add(3 * time.Second), true},
		{"killed: until it would have been called offline", rec(Offline, last, nil), last.Add(offlineBeats * 5 * time.Second), true},
		{"killed: not after that", rec(Offline, last, nil), last.Add(offlineBeats*5*time.Second + time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.CanHaveServedAt(tc.at); got != tc.want {
				t.Fatalf("CanHaveServedAt = %v, want %v", got, tc.want)
			}
		})
	}
}

// A use case whose requests arrive at the LLM gateway is served only by a
// process with the gateway role, whatever other process has read its file.
func TestProveServed_CountsOnlyProcessesOfTheRole(t *testing.T) {
	proc := func(id string, roles ...string) Process {
		return Process{Record: Record{InstanceID: id, Roles: roles, Catalog: &Catalog{Agents: []Agent{{Name: "app", PolicyDigest: "d1"}}}}, Assessed: Running, Current: true}
	}
	proxyOnly := View{Processes: []Process{proc("px", RoleMCPProxy)}}
	if got := ProveLoaded(proxyOnly, true, "app", "", "d1").State; got != LoadedMatchesFile {
		t.Fatalf("a Talon process has read the file: ProveLoaded = %s", got)
	}
	if got := ProveServed(proxyOnly, true, RoleGateway, "app", "", "d1").State; got == LoadedMatchesFile {
		t.Fatalf("no gateway process runs, yet ProveServed(gateway) = %s", got)
	}
	both := View{Processes: []Process{proc("px", RoleMCPProxy), proc("gw", RoleGateway)}}
	if got := ProveServed(both, true, RoleGateway, "app", "", "d1").State; got != LoadedMatchesFile {
		t.Fatalf("a gateway process loaded it: ProveServed(gateway) = %s", got)
	}
	if got := ProveServed(proxyOnly, true, "", "app", "", "d1").State; got != LoadedMatchesFile {
		t.Fatalf("any role: ProveServed = %s", got)
	}
}
