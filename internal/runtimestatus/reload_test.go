package runtimestatus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// #575. What the running processes report about re-reading agent files,
// and how it is worded for an operator. Only running processes of the role
// count; a record without the interval (an earlier release) is not given
// one.
func TestReloadFactsOf(t *testing.T) {
	proc := func(state string, roles []string, c *Catalog) Process {
		return Process{Record: Record{Roles: roles, Catalog: c}, Assessed: state, Current: state == Running}
	}
	gw := []string{RoleGateway, RoleMCP}
	native := []string{RoleNative, RoleMCP}
	every := func(d time.Duration) *Catalog {
		return &Catalog{ReloadEnabled: true, ReloadIntervalMs: d.Milliseconds()}
	}
	cases := []struct {
		name    string
		v       View
		role    string
		want    ReloadFacts
		setting string
	}{
		{"nothing running", View{}, "", ReloadFacts{}, "agents_reload_interval"},
		{"a stale process says nothing", View{Processes: []Process{proc(Stale, gw, every(2*time.Second))}}, "", ReloadFacts{}, "agents_reload_interval"},
		{"no catalog reported", View{Processes: []Process{proc(Running, gw, nil)}}, "", ReloadFacts{}, "agents_reload_interval"},
		{"one interval", View{Processes: []Process{proc(Running, gw, every(2*time.Second))}}, RoleGateway, ReloadFacts{Known: true, Every: 2 * time.Second}, "every 2s, agents_reload_interval"},
		{"sub-second precision is kept", View{Processes: []Process{proc(Running, gw, every(1500*time.Millisecond))}}, "", ReloadFacts{Known: true, Every: 1500 * time.Millisecond}, "every 1.5s, agents_reload_interval"},
		{"reload disabled", View{Processes: []Process{proc(Running, gw, &Catalog{})}}, "", ReloadFacts{Known: true, Disabled: true}, "agents_reload_interval"},
		{"an earlier release does not report its interval", View{Processes: []Process{proc(Running, gw, &Catalog{ReloadEnabled: true})}}, "", ReloadFacts{Known: true, Unreported: true}, "agents_reload_interval"},
		{"different intervals: the longest bounds the next re-scan", View{Processes: []Process{proc(Running, gw, every(2*time.Second)), proc(Running, gw, every(30*time.Second))}}, "", ReloadFacts{Known: true, Every: 30 * time.Second, Varies: true}, "within 30s, agents_reload_interval"},
		{"another role does not count", View{Processes: []Process{proc(Running, native, &Catalog{}), proc(Running, gw, every(2*time.Second))}}, RoleGateway, ReloadFacts{Known: true, Every: 2 * time.Second}, "every 2s, agents_reload_interval"},
		{"a rejected re-scan names its causes", View{Processes: []Process{proc(Running, gw, &Catalog{ReloadEnabled: true, ReloadIntervalMs: 2000, ReloadRejected: true, RejectedCauses: []string{"agents/b/agent.talon.yaml: duplicate agent name"}})}}, "", ReloadFacts{Known: true, Every: 2 * time.Second, RejectedCauses: []string{"agents/b/agent.talon.yaml: duplicate agent name"}}, "every 2s, agents_reload_interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReloadFactsOf(tc.v, tc.role)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.setting, got.Setting())
		})
	}
}
