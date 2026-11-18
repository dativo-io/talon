package runtimestatus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProveGatewayAndProxy(t *testing.T) {
	gw := func(id, state, agentDigest, cfgDigest string) Process {
		p := Process{Record: Record{InstanceID: id, Roles: []string{RoleGateway}, Catalog: &Catalog{Agents: []Agent{{Name: "hr", PolicyDigest: agentDigest}}}}, Assessed: state, Current: true}
		if cfgDigest != "" {
			p.GatewayConfig = &ConfigRef{Digest: cfgDigest}
		}
		return p
	}
	px := func(id, state, cfgDigest string) Process {
		return Process{Record: Record{InstanceID: id, Roles: []string{RoleMCPProxy}, ProxyConfig: &ConfigRef{Digest: cfgDigest}}, Assessed: state, Current: true}
	}
	gwCases := []struct {
		name     string
		procs    []Process
		readable bool
		cfg      string // current gateway config digest
		want     string
	}{
		{"records unreadable", nil, false, "g1", BoundaryUnknown},
		{"no gateway runs (proxy only)", []Process{px("p", Running, "x")}, true, "g1", BoundaryNotRunning},
		{"stale gateway proves nothing", []Process{gw("a", Stale, "d1", "g1")}, true, "g1", BoundaryNotRunning},
		{"agent and gateway config match", []Process{gw("a", Running, "d1", "g1")}, true, "g1", BoundaryProven},
		{"gateway config edited, not restarted", []Process{gw("a", Running, "d1", "g0")}, true, "g1", BoundaryDiffers},
		{"agent file edited, not reloaded", []Process{gw("a", Running, "d0", "g1")}, true, "g1", BoundaryDiffers},
		{"use case not in the gateway's generation", []Process{{Record: Record{InstanceID: "a", Roles: []string{RoleGateway}, Catalog: &Catalog{}, GatewayConfig: &ConfigRef{Digest: "g1"}}, Assessed: Running}}, true, "g1", BoundaryDiffers},
		{"gateway did not report its config", []Process{gw("a", Running, "d1", "")}, true, "g1", BoundaryUnknown},
		{"one of two gateways is stale on config", []Process{gw("a", Running, "d1", "g1"), gw("b", Running, "d1", "g0")}, true, "g1", BoundaryDiffers},
	}
	for _, tc := range gwCases {
		t.Run("gateway/"+tc.name, func(t *testing.T) {
			got := ProveGateway(View{Processes: tc.procs}, tc.readable, "hr", "", "d1", tc.cfg)
			assert.Equal(t, tc.want, got.State, got.Reason)
			assert.NotEmpty(t, got.Reason)
		})
	}
	pxCases := []struct {
		name  string
		procs []Process
		want  string
	}{
		{"no proxy runs (gateway only)", []Process{gw("a", Running, "d1", "g1")}, BoundaryNotRunning},
		{"proxy loaded the current file", []Process{px("p", Running, "p1")}, BoundaryProven},
		{"proxy config edited, not restarted", []Process{px("p", Running, "p0")}, BoundaryDiffers},
	}
	for _, tc := range pxCases {
		t.Run("proxy/"+tc.name, func(t *testing.T) {
			got := ProveProxy(View{Processes: tc.procs}, true, "p1")
			assert.Equal(t, tc.want, got.State, got.Reason)
		})
	}
}

// The Action Gateway is served by every talon serve, so its proof covers
// every running serve process, and loading the gateway's files is not
// enough: the process must report the gateway config it read the company
// action policy from.
func TestProveActionPolicy(t *testing.T) {
	serve := func(id, role, state, agentDigest, cfgDigest string) Process {
		p := Process{Record: Record{InstanceID: id, Roles: []string{role}, Catalog: &Catalog{Agents: []Agent{{Name: "refund-bot", TenantID: "acme", PolicyDigest: agentDigest}}}}, Assessed: state, Current: true}
		if cfgDigest != "" {
			p.GatewayConfig = &ConfigRef{Digest: cfgDigest}
		}
		return p
	}
	console := Process{Record: Record{InstanceID: "ui", Roles: []string{RoleMCPProxy}, ProxyConfig: &ConfigRef{Digest: "p1"}}, Assessed: Running}
	for _, tc := range []struct {
		name     string
		procs    []Process
		readable bool
		want     string
	}{
		{"records unreadable", nil, false, BoundaryUnknown},
		{"nothing serves", []Process{console}, true, BoundaryNotRunning},
		{"a stale serve proves nothing", []Process{serve("a", RoleGateway, Stale, "d1", "g1")}, true, BoundaryNotRunning},
		{"agent file and company policy source match", []Process{serve("a", RoleGateway, Running, "d1", "g1")}, true, BoundaryProven},
		{"company policy edited, process not restarted", []Process{serve("a", RoleGateway, Running, "d1", "g0")}, true, BoundaryDiffers},
		{"agent file edited, not reloaded", []Process{serve("a", RoleGateway, Running, "d0", "g1")}, true, BoundaryDiffers},
		{"a native serve does not report the config it read", []Process{serve("n", RoleNative, Running, "d1", "")}, true, BoundaryUnknown},
		{"a proven gateway beside an unreported native serve is not proven", []Process{serve("a", RoleGateway, Running, "d1", "g1"), serve("n", RoleNative, Running, "d1", "")}, true, BoundaryUnknown},
		{"a proven gateway beside a serve on an older company policy", []Process{serve("a", RoleGateway, Running, "d1", "g1"), serve("b", RoleMCPProxy, Running, "d1", "g0")}, true, BoundaryDiffers},
		{"use case missing from a serve's generation", []Process{{Record: Record{InstanceID: "a", Roles: []string{RoleGateway}, Catalog: &Catalog{}, GatewayConfig: &ConfigRef{Digest: "g1"}}, Assessed: Running}}, true, BoundaryDiffers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ProveActionPolicy(View{Processes: tc.procs}, tc.readable, "refund-bot", "acme", "d1", "g1")
			assert.Equal(t, tc.want, got.State, got.Reason)
			assert.NotEmpty(t, got.Reason)
		})
	}
	// The gateway proof alone would have called the mixed case proven.
	mixed := View{Processes: []Process{serve("a", RoleGateway, Running, "d1", "g1"), serve("n", RoleNative, Running, "d1", "")}}
	assert.Equal(t, BoundaryProven, ProveGateway(mixed, true, "refund-bot", "acme", "d1", "g1").State)
	assert.NotEqual(t, BoundaryProven, ProveActionPolicy(mixed, true, "refund-bot", "acme", "d1", "g1").State)
}
