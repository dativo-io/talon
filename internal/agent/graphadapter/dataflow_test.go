package graphadapter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func TestBuildGraphRunDataFlow_ModelObserved(t *testing.T) {
	df := buildGraphRunDataFlow("gpt-4o", "langgraph", 0.01)
	require.NotNil(t, df)
	require.Len(t, df.Items, 1)
	item := df.Items[0]
	assert.Equal(t, evidence.FlowSourcePrompt, item.Source)
	assert.Equal(t, "orchestrator-reported", item.SourceDetail)
	assert.Equal(t, evidence.FlowDispositionForwarded, item.Disposition)
	assert.Equal(t, evidence.FlowDestLLMProvider, item.Destination.Kind)
	assert.Equal(t, "external:langgraph", item.Destination.Name)
	assert.Equal(t, "gpt-4o", item.Destination.Model)
	assert.Equal(t, evidence.FlowRegionUnknown, item.Destination.Region, "Talon never guesses a region")
	assert.Empty(t, item.EntityTypes, "content never transited Talon — no classification ran")
	assert.Empty(t, df.Detector)
}

func TestBuildGraphRunDataFlow_NoModelNoCost_NotRecorded(t *testing.T) {
	assert.Nil(t, buildGraphRunDataFlow(unknownGraphModel, "langgraph", 0),
		"recording a flow with no sign of a model call would overstate")
	assert.Nil(t, buildGraphRunDataFlow("", "", 0))
}

func TestBuildGraphRunDataFlow_CostWithoutModel(t *testing.T) {
	df := buildGraphRunDataFlow(unknownGraphModel, "", 0.05)
	require.NotNil(t, df, "non-zero cost implies model calls happened")
	require.Len(t, df.Items, 1)
	assert.Equal(t, "external", df.Items[0].Destination.Name)
	assert.Empty(t, df.Items[0].Destination.Model)
}

func TestHandleEvent_RunEnd_RecordsDataFlow(t *testing.T) {
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(nil, gen, store)

	start := &Event{
		Type:       EventRunStart,
		GraphRunID: "gr_flow_1",
		TenantID:   "acme",
		AgentID:    "graph-agent",
		Timestamp:  time.Now(),
		RunMeta:    &RunMeta{Framework: "langgraph", Model: "gpt-4o"},
	}
	_, err := adapter.HandleEvent(context.Background(), start)
	require.NoError(t, err)

	end := &Event{
		Type:       EventRunEnd,
		GraphRunID: "gr_flow_1",
		TenantID:   "acme",
		AgentID:    "graph-agent",
		Timestamp:  time.Now(),
		Cost:       0.02,
		Result:     &ResultMeta{Status: "completed", DurationMS: 1200},
	}
	dec, err := adapter.HandleEvent(context.Background(), end)
	require.NoError(t, err)
	require.NotEmpty(t, dec.EvidenceID)

	records, err := store.List(context.Background(), "acme", "", time.Time{}, time.Time{}, 20)
	require.NoError(t, err)
	var runEnd *evidence.Evidence
	for i := range records {
		if records[i].InvocationType == "graph_run" {
			runEnd = &records[i]
			break
		}
	}
	require.NotNil(t, runEnd, "run_end must produce a graph_run evidence record")
	require.NotNil(t, runEnd.DataFlow, "graph runs with model calls must record data flow")
	require.Len(t, runEnd.DataFlow.Items, 1)
	assert.Equal(t, "external:langgraph", runEnd.DataFlow.Items[0].Destination.Name)
	assert.Equal(t, "gpt-4o", runEnd.DataFlow.Items[0].Destination.Model)
}

func TestHandleEvent_RunEnd_NoModelCall_NoDataFlow(t *testing.T) {
	gen, store := newEvidenceStack(t)
	adapter := NewAdapter(nil, gen, store)

	end := &Event{
		Type:       EventRunEnd,
		GraphRunID: "gr_flow_2",
		TenantID:   "acme",
		AgentID:    "graph-agent",
		Timestamp:  time.Now(),
		Result:     &ResultMeta{Status: "completed"},
	}
	_, err := adapter.HandleEvent(context.Background(), end)
	require.NoError(t, err)

	records, err := store.List(context.Background(), "acme", "", time.Time{}, time.Time{}, 20)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Nil(t, records[0].DataFlow,
		"no model observed and zero cost: claiming a flow would overstate")
}
