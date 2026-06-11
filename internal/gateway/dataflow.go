package gateway

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
)

// dataFlowInputs carries the in-memory request state needed to build the
// data-flow evidence section. Raw text and entity values never leave this
// function chain — only digests reach the evidence record.
type dataFlowInputs struct {
	CorrelationID    string
	TenantID         string
	CallerName       string
	Provider         string
	Model            string
	Allowed          bool
	InputPIIRedacted bool
	InputText        string // extracted request text (for span merging); in-memory only
	Classification   *classifier.Classification
	AttSummary       *AttachmentsScanSummary
	ResponsePII      *ResponsePIIScanResult
	CacheHit         bool
	CacheEntryID     string
	CacheStored      bool
}

// buildDataFlow builds the data_flow evidence section for a gateway request.
// Every request records at least the prompt -> destination flow: data
// movement is evidence even when no PII was detected (GDPR Art. 30 recipients
// and transfers must cover all governed traffic, not only classified data).
// It consumes only the engine-neutral classifier.Classification, so any
// Analyzer implementation plugs in unchanged.
func (g *Gateway) buildDataFlow(in dataFlowInputs) *evidence.DataFlow {
	providerDest := evidence.FlowDestination{
		Kind:     evidence.FlowDestLLMProvider,
		Name:     in.Provider,
		Model:    in.Model,
		Endpoint: g.providerEndpointHost(in.Provider),
		Region:   g.providerRegion(in.Provider),
	}
	// On a cache hit nothing egresses to the provider: the prompt was matched
	// against the tenant-scoped cache instead.
	requestDest := providerDest
	if in.CacheHit {
		requestDest = evidence.FlowDestination{
			Kind: evidence.FlowDestCache,
			Name: in.CacheEntryID,
		}
	}

	requestDisposition := evidence.FlowDispositionForwarded
	switch {
	case !in.Allowed:
		requestDisposition = evidence.FlowDispositionBlocked
	case in.InputPIIRedacted:
		requestDisposition = evidence.FlowDispositionRedacted
	}

	var items []evidence.DataFlowItem

	// Prompt -> provider (or cache). Always recorded, classified or not.
	promptTier := 0
	var promptEntities []classifier.PIIEntity
	if in.Classification != nil {
		promptTier = in.Classification.Tier
		if in.Classification.HasPII {
			promptEntities = classifier.MergeEntitySpans(in.InputText, in.Classification.Entities)
		}
	}
	items = append(items, evidence.NewDataFlowItem(
		in.TenantID, in.CorrelationID,
		evidence.FlowSourcePrompt, "",
		promptTier, promptEntities,
		requestDisposition, requestDest))

	// PII-bearing attachments -> provider (or cache). Attachment scans retain
	// entity types only (no values/positions), so no digests here.
	if in.AttSummary != nil {
		for _, r := range in.AttSummary.Results {
			if !r.PIIFound {
				continue
			}
			disposition := requestDisposition
			if r.ActionTaken == "blocked" || r.ActionTaken == "stripped" {
				disposition = evidence.FlowDispositionBlocked
			}
			items = append(items, evidence.NewDataFlowItemFromTypes(
				evidence.FlowSourceAttachment, r.Filename,
				r.Tier, r.PIITypes,
				disposition, requestDest))
		}
	}

	// Response -> client (and cache, when stored after a forward).
	items = append(items, responseFlowItems(in)...)

	return &evidence.DataFlow{
		Detector: g.classifier.Detector(),
		Items:    items,
	}
}

// responseFlowItems builds flow items for classified response content: one to
// the client, plus one to the semantic cache when the response was stored.
func responseFlowItems(in dataFlowInputs) []evidence.DataFlowItem {
	if in.ResponsePII == nil || !in.ResponsePII.PIIDetected {
		return nil
	}
	disposition := evidence.FlowDispositionSurfaced
	switch {
	case in.ResponsePII.Blocked:
		disposition = evidence.FlowDispositionBlocked
	case in.ResponsePII.Redacted:
		disposition = evidence.FlowDispositionRedacted
	}
	items := []evidence.DataFlowItem{evidence.NewDataFlowItem(
		in.TenantID, in.CorrelationID,
		evidence.FlowSourceResponse, "",
		in.ResponsePII.Tier, in.ResponsePII.Entities,
		disposition, evidence.FlowDestination{
			Kind: evidence.FlowDestClient,
			Name: in.CallerName,
		})}
	if in.CacheStored {
		items = append(items, evidence.NewDataFlowItem(
			in.TenantID, in.CorrelationID,
			evidence.FlowSourceResponse, "",
			in.ResponsePII.Tier, in.ResponsePII.Entities,
			disposition, evidence.FlowDestination{
				Kind: evidence.FlowDestCache,
			}))
	}
	return items
}

// emitDataFlowTelemetry attaches data-flow attributes to the current span and
// emits a structured log line. Types, counts, and destinations only — never
// raw values or digests.
func (g *Gateway) emitDataFlowTelemetry(ctx context.Context, correlationID string, caller *CallerConfig, df *evidence.DataFlow) {
	if df == nil || len(df.Items) == 0 {
		return
	}
	destSet := make(map[string]struct{}, len(df.Items))
	regionSet := make(map[string]struct{}, len(df.Items))
	typeCount := 0
	for i := range df.Items {
		item := &df.Items[i]
		destSet[item.Destination.Kind+":"+item.Destination.Name] = struct{}{}
		if item.Destination.Region != "" {
			regionSet[item.Destination.Region] = struct{}{}
		}
		typeCount += len(item.EntityTypes)
	}
	destinations := setToSortedCSV(destSet)
	regions := setToSortedCSV(regionSet)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(
			attribute.String("talon.data_flow.destinations", destinations),
			attribute.String("talon.data_flow.regions", regions),
			attribute.Int("talon.data_flow.item_count", len(df.Items)),
			attribute.Int("talon.data_flow.entity_type_count", typeCount),
		)
	}
	log.Info().
		Str("correlation_id", correlationID).
		Str("tenant_id", caller.TenantID).
		Str("agent_id", caller.Name).
		Str("flow_destinations", destinations).
		Str("flow_regions", regions).
		Int("flow_items", len(df.Items)).
		Msg("data_flow_recorded")
}

func setToSortedCSV(set map[string]struct{}) string {
	if len(set) == 0 {
		return ""
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// providerRegion resolves the jurisdiction of a gateway provider: explicit
// gateway config region first, then registered provider metadata, then
// "unknown". Talon never guesses a region.
func (g *Gateway) providerRegion(provider string) string {
	if prov, ok := g.config.Provider(provider); ok && prov.Region != "" {
		return normalizeEgressRegion(prov.Region)
	}
	if j := llm.JurisdictionForProvider(provider); j != "" {
		return normalizeEgressRegion(j)
	}
	return evidence.FlowRegionUnknown
}

// providerEndpointHost returns the host of the configured upstream base URL
// (never path, query, or credentials).
func (g *Gateway) providerEndpointHost(provider string) string {
	prov, ok := g.config.Provider(provider)
	if !ok || prov.BaseURL == "" {
		return ""
	}
	u, err := url.Parse(prov.BaseURL)
	if err != nil {
		return ""
	}
	return u.Host
}
