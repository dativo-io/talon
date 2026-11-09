package evidence

import (
	"fmt"
	"strings"

	"github.com/dativo-io/talon/internal/explanation"
)

// Outcome states what one evidence record proves about the request or
// operation it describes, on separate axes: Talon's policy decision, whether
// the request left Talon (dispatch), and what the destination did
// (downstream). It is derived only from facts the writing code path records,
// rule by rule below; when a record carries no such fact the axis is
// "not_recorded", never a guess. Basis names the recorded fact the axis was
// read from, so a consumer can show why (#541).
//
// The console renders this projection; it never classifies records itself.
type Outcome struct {
	Decision   string `json:"decision"`   // allowed | denied
	Dispatch   string `json:"dispatch"`   // see Dispatch* constants
	Downstream string `json:"downstream"` // see Downstream* constants
	// ResponseWithheld: the destination answered but Talon did not return the
	// answer (output scanning failed closed or blocked it).
	ResponseWithheld bool   `json:"response_withheld,omitempty"`
	Tool             string `json:"tool,omitempty"`
	Basis            string `json:"basis"`
}

// Dispatch states.
const (
	DispatchNotDispatched = "not_dispatched" // the request never left Talon
	DispatchDispatched    = "dispatched"     // the request reached the destination
	DispatchUnknown       = "unknown"        // it may have; no reliable observation
	DispatchNotRecorded   = "not_recorded"   // this record type carries no dispatch fact
)

// Downstream states.
const (
	DownstreamNone        = "none"         // nothing was sent, so nothing answered
	DownstreamCompleted   = "completed"    // the destination answered successfully
	DownstreamRejected    = "rejected"     // the destination answered with its own error
	DownstreamFailed      = "failed"       // the attempt failed (transport or provider error)
	DownstreamUnknown     = "unknown"      // the effect may exist; no trustworthy answer
	DownstreamNotRecorded = "not_recorded" // this record type carries no downstream fact
	DownstreamCache       = "cache"        // Talon answered from its semantic cache; no destination was involved
)

// OutcomeOf projects ev. Rules, in order:
//
//   - action_lifecycle records: the attempt's result provenance
//     (observed / not_dispatched / unknown) and attempt status, as recorded
//     by the action dispatcher; an authorization_refused event dispatched
//     nothing.
//   - proxy_tool_blocked: written only on the MCP proxy's pre-dispatch deny
//     path (internal/mcp/proxy.go), so nothing reached the upstream.
//   - proxy_upstream_error: status "unknown" means the request was handed to
//     the transport and no trustworthy answer came back; a vendor JSON-RPC
//     error ("upstream_jsonrpc_error…") means the call executed and the
//     vendor rejected it; any other failure happened before the transport.
//   - proxy_tool_call: the call was forwarded and answered; a denied
//     proxy_tool_call is an answer Talon withheld (output scanning).
//   - gateway cache hits (cache_hit true): Talon served the response from its
//     semantic cache and returned without contacting a provider
//     (internal/gateway: recordEvidence then writeCachedCompletion).
//   - gateway / gateway_failover_attempt failures: dispatched only when the
//     record carries the provider's HTTP status (failover.upstream_status),
//     which proves an answer came back; a transport failure without one
//     (connection error, timeout, cancellation) may have happened before or
//     after delivery, so dispatch is unknown.
//   - an allowed gateway record without an error reached the provider and was
//     answered; a denied one whose primary explanation stage is
//     policy_evaluation or pre_execution was refused before the provider, one
//     denied at output_validation was answered and withheld.
//   - anything else: decision only; dispatch and downstream not_recorded.
func OutcomeOf(ev *Evidence) Outcome {
	out := Outcome{Decision: "denied", Dispatch: DispatchNotRecorded, Downstream: DownstreamNotRecorded}
	if ev.PolicyDecision.Allowed {
		out.Decision = "allowed"
	}
	if len(ev.Execution.ToolsCalled) > 0 {
		out.Tool = ev.Execution.ToolsCalled[0]
	}
	switch ev.InvocationType {
	case InvocationTypeActionLifecycle:
		actionOutcome(ev, &out)
	case "proxy_tool_blocked":
		out.Dispatch, out.Downstream = DispatchNotDispatched, DownstreamNone
		out.Basis = "proxy_tool_blocked: recorded on the MCP proxy's pre-dispatch deny path"
	case "proxy_upstream_error":
		upstreamErrorOutcome(ev, &out)
	case "proxy_tool_call":
		out.Dispatch, out.Downstream = DispatchDispatched, DownstreamCompleted
		out.Basis = "proxy_tool_call: forwarded to the upstream and answered"
		if !ev.PolicyDecision.Allowed {
			out.ResponseWithheld = true
			out.Basis = "proxy_tool_call denied after the upstream answered: the answer was withheld"
		}
	case "gateway_failover_attempt":
		providerFailure(ev, &out, "gateway_failover_attempt")
	case "gateway":
		gatewayOutcome(ev, &out)
	default:
		out.Basis = "invocation type " + ev.InvocationType + " records the decision only"
	}
	return out
}

func actionOutcome(ev *Evidence, out *Outcome) {
	al := ev.ActionLifecycle
	switch {
	case al == nil:
		out.Basis = "action_lifecycle record without lifecycle facts"
	case al.Event == ActionEventAuthorizationRefused:
		out.Dispatch, out.Downstream = DispatchNotDispatched, DownstreamNone
		out.Basis = "action lifecycle: authorization_refused"
	case al.ResultProvenance == ResultProvenanceNotDispatched:
		out.Dispatch, out.Downstream = DispatchNotDispatched, DownstreamNone
		out.Basis = "action lifecycle: result provenance not_dispatched"
	case al.ResultProvenance == ResultProvenanceUnknown:
		out.Dispatch, out.Downstream = DispatchUnknown, DownstreamUnknown
		out.Basis = "action lifecycle: result provenance unknown"
	case al.ResultProvenance == ResultProvenanceObserved:
		out.Dispatch, out.Downstream = DispatchDispatched, DownstreamFailed
		if al.AttemptStatus == "succeeded" {
			out.Downstream = DownstreamCompleted
		}
		out.Basis = "action lifecycle: result observed, attempt " + al.AttemptStatus
	default:
		out.Basis = "action lifecycle event " + al.Event + " carries no attempt result"
	}
}

func upstreamErrorOutcome(ev *Evidence, out *Outcome) {
	reason := ev.Execution.Error
	switch {
	case ev.Status == StatusUnknown:
		out.Dispatch, out.Downstream = DispatchUnknown, DownstreamUnknown
		out.Basis = "proxy_upstream_error with status unknown: handed to the transport, no trustworthy answer"
	case strings.HasPrefix(reason, "upstream_jsonrpc_error"):
		out.Dispatch, out.Downstream = DispatchDispatched, DownstreamRejected
		out.Basis = "proxy_upstream_error: the upstream executed the call and returned its own error"
	default:
		out.Dispatch, out.Downstream = DispatchNotDispatched, DownstreamNone
		out.Basis = "proxy_upstream_error before the transport: the call was not sent"
	}
}

// providerFailure reads a failed provider attempt: dispatched only when the
// provider's HTTP status was recorded, unknown otherwise.
func providerFailure(ev *Evidence, out *Outcome, kind string) {
	if f := ev.Failover; f != nil && f.UpstreamStatus > 0 {
		out.Dispatch, out.Downstream = DispatchDispatched, DownstreamFailed
		out.Basis = fmt.Sprintf("%s: the provider answered HTTP %d", kind, f.UpstreamStatus)
		return
	}
	out.Dispatch, out.Downstream = DispatchUnknown, DownstreamUnknown
	class := ""
	if ev.Failover != nil && ev.Failover.ErrorClass != "" {
		class = " (" + ev.Failover.ErrorClass + ")"
	}
	out.Basis = kind + ": failed without a recorded provider response" + class + "; delivery is not proven"
}

func gatewayOutcome(ev *Evidence, out *Outcome) {
	if ev.CacheHit {
		out.Dispatch, out.Downstream = DispatchNotDispatched, DownstreamCache
		out.Basis = "gateway cache hit: answered from Talon's semantic cache, no provider call"
		if ev.CacheEntryID != "" {
			out.Basis += " (cache entry " + ev.CacheEntryID + ")"
		}
		return
	}
	if ev.PolicyDecision.Allowed {
		if ev.Execution.Error != "" {
			providerFailure(ev, out, "allowed gateway record with an execution error")
			return
		}
		out.Dispatch, out.Downstream = DispatchDispatched, DownstreamCompleted
		out.Basis = "allowed gateway record: forwarded to the provider and answered"
		return
	}
	stage := ""
	if primary, ok := explanation.Primary(ev.Explanations); ok {
		stage = primary.Stage
	}
	switch stage {
	case "policy_evaluation", "pre_execution":
		out.Dispatch, out.Downstream = DispatchNotDispatched, DownstreamNone
		out.Basis = "gateway denial at stage " + stage + ": refused before the provider"
	case "output_validation", "output_scan":
		out.Dispatch, out.Downstream, out.ResponseWithheld = DispatchDispatched, DownstreamCompleted, true
		out.Basis = "gateway denial at output validation: the provider answered and the answer was withheld"
	default:
		out.Basis = "gateway denial without a recorded stage"
	}
}
