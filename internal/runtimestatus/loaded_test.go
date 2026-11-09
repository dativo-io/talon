package runtimestatus

import (
	"testing"

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
