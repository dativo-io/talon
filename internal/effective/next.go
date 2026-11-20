package effective

import (
	"strings"

	"github.com/dativo-io/talon/internal/runtimestatus"
)

// NextStep is the one thing an operator would do next for this use case, or
// that nothing needs doing. It is a fixed mapping from facts the report
// already holds (the reading, what the running processes report, the
// credential) to a sentence and, where one exists, a command. It decides
// nothing, stores nothing and recommends only commands that exist; when the
// facts allow several explanations it names the first one to check.
type NextStep struct {
	// Code is stable: none | enable | start_runtime | check_runtime |
	// fix_reload | wait_reload | send_request | send_new_request |
	// check_policy | restart_runtime | use_current_key | store_key |
	// verify_evidence | check_evidence | use_authenticated_boundary.
	Code string `json:"code"`
	Text string `json:"text"`
	// Commands are complete Talon commands that carry out or check the
	// step, in the order to run them. Empty when the step is not a Talon
	// command (starting the server, sending a request).
	Commands []string `json:"commands,omitempty"`
}

// Next step codes.
const (
	NextNone               = "none"
	NextEnable             = "enable"
	NextStartRuntime       = "start_runtime"
	NextCheckRuntime       = "check_runtime"
	NextFixReload          = "fix_reload"
	NextWaitReload         = "wait_reload"
	NextSendRequest        = "send_request"
	NextSendNewRequest     = "send_new_request"
	NextCheckPolicy        = "check_policy"
	NextRestartRuntime     = "restart_runtime"
	NextUseCurrentKey      = "use_current_key"
	NextStoreKey           = "store_key"
	NextVerifyEvidence     = "verify_evidence"
	NextCheckEvidence      = "check_evidence"
	NextUseAuthenticatedBy = "use_authenticated_boundary"
)

// runtimeFacts is what the runtime records say that a next step depends on.
type runtimeFacts struct {
	known    bool     // runtime records were read
	running  bool     // a Talon process of this installation is running
	rejected []string // causes of a reload the running process rejected
}

func runtimeFactsOf(view *runtimestatus.View, readable bool) runtimeFacts {
	f := runtimeFacts{known: view != nil && readable}
	if !f.known {
		return f
	}
	for i := range view.Processes {
		p := &view.Processes[i]
		if p.Assessed != runtimestatus.Running {
			continue
		}
		f.running = true
		if p.Catalog != nil && p.Catalog.ReloadRejected {
			f.rejected = append(f.rejected, p.Catalog.RejectedCauses...)
		}
	}
	return f
}

// nextStepOf maps the report's facts to the next step. name is the use
// case; endpoints are the gateway paths the configuration enables.
func nextStepOf(v *Verification, loaded runtimestatus.Loaded, rt runtimeFacts, name, tenant string, endpoints []string) NextStep {
	effectiveCmd := "talon agents show " + name + " --effective"
	if v.Configured == "disabled" {
		return NextStep{NextEnable, "This use case is disabled in its file: new requests are refused once the running process has loaded that. To serve it again, enable it; the change is active when the running process has reloaded the file.", []string{"talon agents enable " + name}}
	}
	switch v.Reading.Code {
	case ReadingTrafficMatches:
		// A verified request is about the past. "Nothing to do" also needs
		// a running process that serves the use case now.
		if loaded.State != runtimestatus.LoadedMatchesFile {
			step := notServingStep(loaded, rt, name, endpoints)
			step.Text = "The newest request verified, but that was earlier. Now: " + lowerFirst(step.Text)
			return step
		}
		return NextStep{Code: NextNone, Text: "Nothing to do: a running Talon process serves this use case, and the newest request was authenticated, verifies and was evaluated under the policy the current files compile to."}
	case ReadingNotLoaded, ReadingLoadUnknown, ReadingLoadedNoTraffic:
		return notServingStep(loaded, rt, name, endpoints)
	case ReadingTrafficDiffers:
		return NextStep{NextSendNewRequest, "The newest request was evaluated under another policy than the current files compile to. If a policy file changed since, send a new request. If none did, the running process serves other files than the ones on disk: compare sections 2 and 3 of the full report.", []string{effectiveCmd}}
	case ReadingTrafficNotProven:
		return NextStep{NextCheckPolicy, "A request arrived, but its record does not carry the policy it was evaluated under, so that cannot be compared with the current files. The full report says which record and why.", []string{effectiveCmd}}
	case ReadingTrafficHistorical:
		return historicalStep(v, name, tenant)
	case ReadingTrafficCredentialUnproven:
		return NextStep{Code: NextRestartRuntime, Text: "A request arrived after the key was stored, served by a Talon process that was already running before that. To establish that the application uses the key stored now: restart `talon serve`, send one request, and look again."}
	case ReadingTrafficUnverified:
		step := NextStep{Code: NextVerifyEvidence, Text: "The newest record's signature does not verify, so nothing on it is established. Check that this shell has the installation's TALON_SIGNING_KEY, then verify the record."}
		if o := v.newestObserved(); o != nil {
			step.Commands = []string{"talon audit verify " + o.EvidenceID}
		}
		return step
	case ReadingEvidenceUnknown:
		return NextStep{NextCheckEvidence, "The evidence store could not be read, so whether a request arrived is not known. Check the installation.", []string{"talon doctor"}}
	case ReadingTrafficIdentityUnknown:
		return NextStep{Code: NextUseAuthenticatedBy, Text: "Records are attributed to this use case, but none establishes that its own key was presented (MCP proxy and quickstart records do not). To verify the application's connection, send a request with its Talon key through the LLM gateway or the Action Gateway."}
	}
	return NextStep{Code: NextNone, Text: "See the full report.", Commands: []string{effectiveCmd}}
}

// notServingStep covers a use case with no observed traffic: is it the
// runtime (not running, rejected the fleet, has not reloaded yet) or the
// application that has not sent a request?
func notServingStep(loaded runtimestatus.Loaded, rt runtimeFacts, name string, endpoints []string) NextStep {
	_ = name
	switch {
	case loaded.State == runtimestatus.LoadedMatchesFile:
		where := "the gateway endpoint of your Talon server"
		if len(endpoints) > 0 {
			where = "<talon-url>" + strings.Join(endpoints, " or <talon-url>")
		}
		return NextStep{Code: NextSendRequest, Text: "The running Talon process serves this use case; no request has arrived yet. Point the application at " + where + " with its Talon key and send one request. A request with a wrong key is answered 401 and leaves no record here."}
	case rt.known && !rt.running:
		return NextStep{Code: NextStartRuntime, Text: "No Talon process of this installation is running, so nothing serves this use case. Start `talon serve` with this installation's keys; it loads the use case when it starts."}
	case len(rt.rejected) > 0:
		return NextStep{NextFixReload, "The running Talon process rejected the last change to the fleet and keeps serving the previous one: " + strings.Join(rt.rejected, "; ") + ". Fix that; the next re-scan loads the current files.", []string{"talon validate"}}
	case rt.known && rt.running:
		return NextStep{NextWaitReload, "A Talon process is running and has not loaded the current version of this use case yet. It re-scans agents_dir periodically (agents_reload_interval, default 30s): look again in a moment. If it stays like this, check the fleet.", []string{"talon validate"}}
	}
	return NextStep{Code: NextCheckRuntime, Text: "Whether a Talon process serves this use case is not known here: this installation's runtime records could not be read. Look from the host that runs `talon serve`, with the installation's keys."}
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// historicalStep covers traffic that was authenticated with a credential
// that is not the one stored now.
func historicalStep(v *Verification, name, tenant string) NextStep {
	c := v.Credential
	switch {
	case c != nil && c.State == CredentialAbsent:
		return NextStep{NextStoreKey, "No key is stored for this use case (it was removed), so the application cannot authenticate. Store a new key through stdin, restart `talon serve` and give the key to the application.", []string{`printf '%s' "$NEW_KEY" | talon secrets set ` + c.SecretName + " --tenant " + tenant + " --agent " + name}}
	case c != nil && c.Runtime == RuntimePredatesCurrent:
		return NextStep{Code: NextRestartRuntime, Text: "The key was replaced, and the running Talon process still holds the earlier one. Restart `talon serve`, give the new key to the application, send one request and look again."}
	}
	return NextStep{Code: NextUseCurrentKey, Text: "Every request so far used an earlier key of this use case (it was registered again, or its key was replaced). Give the current key to the application, send one request and look again."}
}
