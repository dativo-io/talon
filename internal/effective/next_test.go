package effective

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/runtimestatus"
)

// The next step is a fixed mapping from facts to one sentence and, where a
// Talon command exists for it, that command. Every reading has a step, a
// step never recommends a deletion, and "nothing to do" is said only when
// the newest request verified under the current policy.
func TestNextStep_IsDeterminedByTheFacts(t *testing.T) {
	running := runtimeFacts{known: true, running: true}
	stopped := runtimeFacts{known: true}
	rejected := runtimeFacts{known: true, running: true, rejected: []string{"agents/broken/agent.talon.yaml: field typo_field not found"}}
	loaded := runtimestatus.Loaded{State: runtimestatus.LoadedMatchesFile}
	notLoaded := runtimestatus.Loaded{State: runtimestatus.NotInActiveGeneration}
	endpoints := []string{"/v1/proxy/openai/v1"}
	v := func(code string, mod ...func(*Verification)) *Verification {
		out := &Verification{Configured: "enabled", Reading: Reading{Code: code}}
		for _, m := range mod {
			m(out)
		}
		return out
	}

	cases := []struct {
		name     string
		v        *Verification
		loaded   runtimestatus.Loaded
		rt       runtimeFacts
		code     string
		contains []string
		commands []string
	}{
		{"verified and served now", v(ReadingTrafficMatches), loaded, running, NextNone, []string{"Nothing to do", "a running Talon process serves this use case"}, nil},
		{"verified earlier, nothing runs now", v(ReadingTrafficMatches), runtimestatus.Loaded{State: runtimestatus.LoadedUnknown}, stopped, NextStartRuntime, []string{"verified, but that was earlier", "no Talon process of this installation is running"}, nil},
		{"verified earlier, the running process dropped it", v(ReadingTrafficMatches), notLoaded, rejected, NextFixReload, []string{"verified, but that was earlier", "rejected the last change to the fleet"}, []string{"talon validate"}},
		{"disabled wins over everything", v(ReadingTrafficMatches, func(v *Verification) { v.Configured = "disabled" }), loaded, running, NextEnable, []string{"disabled in its file"}, []string{"talon agents enable app"}},
		{"registered, nothing running", v(ReadingNotLoaded), notLoaded, stopped, NextStartRuntime, []string{"No Talon process of this installation is running"}, nil},
		{"registered, the running process rejected the fleet", v(ReadingNotLoaded), notLoaded, rejected, NextFixReload, []string{"rejected the last change to the fleet", "typo_field"}, []string{"talon validate"}},
		{"registered, the running process has not reloaded yet", v(ReadingNotLoaded), notLoaded, running, NextWaitReload, []string{"has not loaded the current version of this use case yet"}, []string{"talon validate"}},
		{"runtime records unreadable", v(ReadingLoadUnknown), runtimestatus.Loaded{State: runtimestatus.LoadedUnknown}, runtimeFacts{}, NextCheckRuntime, []string{"is not known here"}, nil},
		{"loaded, no traffic", v(ReadingLoadedNoTraffic), loaded, running, NextSendRequest, []string{"<talon-url>/v1/proxy/openai/v1", "answered 401 and leaves no record"}, nil},
		{"policy differs", v(ReadingTrafficDiffers), loaded, running, NextSendNewRequest, []string{"another policy"}, []string{"talon agents show app --effective"}},
		{"policy not proven", v(ReadingTrafficNotProven), loaded, running, NextCheckPolicy, []string{"does not carry the policy"}, []string{"talon agents show app --effective"}},
		{"only earlier-key traffic", v(ReadingTrafficHistorical, func(v *Verification) {
			v.Credential = &Credential{State: CredentialKnown, Runtime: RuntimeHoldsCurrent}
		}), loaded, running, NextUseCurrentKey, []string{"earlier key"}, nil},
		{"key replaced, process not restarted", v(ReadingTrafficHistorical, func(v *Verification) {
			v.Credential = &Credential{State: CredentialKnown, Runtime: RuntimePredatesCurrent}
		}), loaded, running, NextRestartRuntime, []string{"still holds the earlier one", "Restart `talon serve`"}, nil},
		{"key removed", v(ReadingTrafficHistorical, func(v *Verification) {
			v.Credential = &Credential{State: CredentialAbsent, SecretName: "app-talon-key"}
		}), loaded, running, NextStoreKey, []string{"No key is stored"}, []string{`printf '%s' "$NEW_KEY" | talon secrets set app-talon-key --tenant acme --agent app`}},
		{"current key not established", v(ReadingTrafficCredentialUnproven), loaded, running, NextRestartRuntime, []string{"restart `talon serve`, send one request"}, nil},
		{"record does not verify", v(ReadingTrafficUnverified, func(v *Verification) {
			v.Traffic = []TrafficObservation{{Boundary: BoundaryLLMGateway, State: TrafficObserved, EvidenceID: "gw_1"}}
		}), loaded, running, NextVerifyEvidence, []string{"does not verify", "TALON_SIGNING_KEY"}, nil},
		{"evidence unreadable", v(ReadingEvidenceUnknown), loaded, running, NextCheckEvidence, []string{"could not be read"}, []string{"talon doctor"}},
		{"only unauthenticated boundaries", v(ReadingTrafficIdentityUnknown), loaded, running, NextUseAuthenticatedBy, []string{"none establishes that its own key was presented"}, nil},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nextStepOf(tc.v, tc.loaded, tc.rt, "app", "acme", endpoints)
			assert.Equal(t, tc.code, got.Code)
			for _, want := range tc.contains {
				assert.Contains(t, got.Text, want)
			}
			if tc.commands != nil {
				assert.Equal(t, tc.commands, got.Commands)
			}
			for _, bad := range []string{"rm ", "secrets delete", "rmdir"} {
				assert.NotContains(t, got.Text+strings.Join(got.Commands, " "), bad, "a next step never recommends a deletion")
			}
			if got.Code == NextNone {
				assert.Equal(t, ReadingTrafficMatches, tc.v.Reading.Code, "'nothing to do' needs verified traffic")
				assert.Equal(t, runtimestatus.LoadedMatchesFile, tc.loaded.State, "and a running process that serves the use case now")
			}
		})
		seen[tc.v.Reading.Code] = true
	}
	for _, code := range []string{
		ReadingDisabled, ReadingEvidenceUnknown, ReadingNotLoaded, ReadingLoadUnknown, ReadingLoadedNoTraffic, ReadingTrafficMatches,
		ReadingTrafficDiffers, ReadingTrafficNotProven, ReadingTrafficUnverified, ReadingTrafficIdentityUnknown, ReadingTrafficHistorical, ReadingTrafficCredentialUnproven,
	} {
		if code == ReadingDisabled {
			continue // reached through Configured, covered above
		}
		assert.True(t, seen[code], "no next step is tested for reading %s", code)
	}
}
