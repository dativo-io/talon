// Data-flow evidence for externally orchestrated graph runs. Content never
// transits Talon on this path — the external runtime (LangGraph, LangChain,
// OpenAI SDK) calls the model provider directly and self-reports governance
// events. Talon signs what the orchestrator reported: that prompts were sent
// to a model. No classification ran (empty detector, no entity types) and the
// provider region is unknown unless declared — Talon never guesses. Routing
// the traffic through the Talon gateway upgrades this to observed,
// classified data flow.
package graphadapter

import (
	"strings"

	"github.com/dativo-io/talon/internal/evidence"
)

// externalRuntimeDest is the destination name prefix for orchestrator-reported
// flows where the concrete LLM provider is not known to Talon.
const externalRuntimeDest = "external"

// buildGraphRunDataFlow builds the data_flow section for a graph run_end
// record. Returns nil when there is no indication that any model call
// happened (no model observed and zero cost) — recording a flow then would
// overstate. Otherwise records one prompt -> external-runtime item.
func buildGraphRunDataFlow(modelUsed, framework string, cost float64) *evidence.DataFlow {
	hasModel := modelUsed != "" && modelUsed != unknownGraphModel
	if !hasModel && cost <= 0 {
		return nil
	}

	name := externalRuntimeDest
	if f := strings.TrimSpace(framework); f != "" {
		name = externalRuntimeDest + ":" + f
	}
	model := ""
	if hasModel {
		model = modelUsed
	}

	return &evidence.DataFlow{
		// Detector left empty: content never transited Talon, no classification ran.
		Items: []evidence.DataFlowItem{{
			Source:       evidence.FlowSourcePrompt,
			SourceDetail: "orchestrator-reported",
			Disposition:  evidence.FlowDispositionForwarded,
			Destination: evidence.FlowDestination{
				Kind:   evidence.FlowDestLLMProvider,
				Name:   name,
				Model:  model,
				Region: evidence.FlowRegionUnknown,
			},
		}},
	}
}
