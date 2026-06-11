// Data-flow evidence for agent runs: links the prompt (and classified
// response) of every CLI, scheduled, or webhook run to its destination.
// Every run that egresses records at least the prompt -> destination flow —
// data movement is evidence even when no PII was detected, so GDPR Art. 30
// recipients and transfers cover all governed traffic.
package agent

import (
	"strings"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
)

// runFlowInputs carries the request state needed to build the data_flow
// evidence section for one agent run. Entity types only — never raw values.
type runFlowInputs struct {
	TenantID       string
	InvocationType string // "manual", "scheduled", "webhook:<name>" — the response recipient

	// Destination: LLM provider, or the semantic cache on a cache hit.
	Provider     string
	Model        string
	CacheHit     bool
	CacheEntryID string

	InputTier        int
	InputPIITypes    []string
	InputPIIRedacted bool

	OutputTier     int
	OutputPIITypes []string
	OutputRedacted bool
	OutputBlocked  bool

	Detector string
}

// buildRunDataFlow builds the data_flow section for an agent run. Returns at
// least one item (prompt -> provider/cache); adds response -> client when the
// response carried PII or was blocked by output policy.
func buildRunDataFlow(in runFlowInputs) *evidence.DataFlow {
	dest := evidence.FlowDestination{
		Kind:   evidence.FlowDestLLMProvider,
		Name:   in.Provider,
		Model:  in.Model,
		Region: providerFlowRegion(in.Provider),
	}
	if in.CacheHit {
		dest = evidence.FlowDestination{
			Kind: evidence.FlowDestCache,
			Name: in.CacheEntryID,
		}
	}

	promptDisposition := evidence.FlowDispositionForwarded
	if in.InputPIIRedacted {
		promptDisposition = evidence.FlowDispositionRedacted
	}
	items := []evidence.DataFlowItem{evidence.NewDataFlowItemFromTypes(
		evidence.FlowSourcePrompt, "",
		in.InputTier, in.InputPIITypes,
		promptDisposition, dest)}

	if len(in.OutputPIITypes) > 0 || in.OutputBlocked {
		disposition := evidence.FlowDispositionSurfaced
		switch {
		case in.OutputBlocked:
			disposition = evidence.FlowDispositionBlocked
		case in.OutputRedacted:
			disposition = evidence.FlowDispositionRedacted
		}
		items = append(items, evidence.NewDataFlowItemFromTypes(
			evidence.FlowSourceResponse, "",
			in.OutputTier, in.OutputPIITypes,
			disposition, evidence.FlowDestination{
				Kind: evidence.FlowDestClient,
				Name: in.InvocationType,
			}))
	}

	return &evidence.DataFlow{Detector: in.Detector, Items: items}
}

// providerFlowRegion resolves the jurisdiction of an LLM provider from its
// registered metadata. Talon never guesses a region: unregistered providers
// resolve to "unknown".
func providerFlowRegion(provider string) string {
	if j := llm.JurisdictionForProvider(provider); j != "" {
		return strings.ToUpper(j)
	}
	return evidence.FlowRegionUnknown
}
