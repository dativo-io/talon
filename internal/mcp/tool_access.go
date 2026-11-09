package mcp

import (
	"context"
	"strings"

	"github.com/dativo-io/talon/internal/policy"
)

// ForbiddenToolMatch reports whether tool matches one of the proxy's
// forbidden_tools entries (exact, or a trailing-* prefix) and which entry.
// The proxy handler blocks a matching call before any policy evaluation and
// before dispatch; explanations use this same function (#305).
func ForbiddenToolMatch(forbidden []string, tool string) (string, bool) {
	for _, f := range forbidden {
		if f == tool || (strings.HasSuffix(f, "*") && strings.HasPrefix(tool, strings.TrimSuffix(f, "*"))) {
			return f, true
		}
	}
	return "", false
}

// ToolAccess is the MCP proxy's pre-dispatch decision for a tool name.
type ToolAccess struct {
	Tool    string   `json:"tool"`
	Allowed bool     `json:"allowed"`
	Stage   string   `json:"stage"`             // forbidden_tools | policy
	Matched string   `json:"matched,omitempty"` // the forbidden_tools entry that matched
	Reasons []string `json:"reasons,omitempty"` // policy deny reasons
	Note    string   `json:"note,omitempty"`
}

// EvaluateToolAccess runs the proxy handler's two pre-dispatch checks in
// order: the forbidden_tools match, then the proxy policy engine's
// tool-access evaluation (the same Rego query the handler runs). Call
// arguments are not known here, so a rule that depends on arguments is
// evaluated without them; Note says so.
func EvaluateToolAccess(ctx context.Context, cfg *policy.ProxyPolicyConfig, engine *policy.ProxyEngine, tool string) (ToolAccess, error) {
	if m, ok := ForbiddenToolMatch(cfg.Proxy.ForbiddenTools, tool); ok {
		return ToolAccess{Tool: tool, Allowed: false, Stage: "forbidden_tools", Matched: m}, nil
	}
	d, err := engine.EvaluateProxyToolAccess(ctx, &policy.ProxyInput{ToolName: tool, Vendor: cfg.Proxy.Upstream.Vendor, UpstreamRegion: upstreamRegionOf(cfg)})
	if err != nil {
		return ToolAccess{}, err
	}
	return ToolAccess{Tool: tool, Allowed: d.Allowed, Stage: "policy", Reasons: d.Reasons, Note: "evaluated without call arguments"}, nil
}
