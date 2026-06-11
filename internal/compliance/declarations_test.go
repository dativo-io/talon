package compliance

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func fullDeclarations() Declarations {
	return Declarations{
		Controller: ControllerDeclarations{
			Name:       "Example GmbH",
			Contact:    "privacy@example.eu",
			DPOContact: "dpo@example.eu",
			Address:    "Examplestr. 1, 10115 Berlin",
		},
		Processing: ProcessingDeclarations{
			Purposes:               []string{"customer support triage"},
			DataSubjectCategories:  []string{"customers"},
			PersonalDataCategories: []string{"contact details"},
			RetentionPeriod:        "90 days",
			Safeguards:             "access restricted to support team",
			LegalBasis:             "contract",
		},
		System: SystemDeclarations{
			SystemDescription:    "LLM assistant for support ticket triage",
			IntendedPurpose:      "Summarize and route inbound support tickets",
			OversightDescription: "Support lead reviews flagged tickets daily",
		},
	}
}

func TestValidateForRoPA(t *testing.T) {
	tests := []struct {
		name         string
		mutate       func(*Declarations)
		wantWarnings int
		wantContains string
	}{
		{
			name:         "complete declarations produce no warnings",
			mutate:       func(*Declarations) {},
			wantWarnings: 0,
		},
		{
			name:         "zero value warns on all expected fields",
			mutate:       func(d *Declarations) { *d = Declarations{} },
			wantWarnings: 5,
			wantContains: "compliance.controller.name",
		},
		{
			name:         "missing controller name",
			mutate:       func(d *Declarations) { d.Controller.Name = "" },
			wantWarnings: 1,
			wantContains: "GDPR Art. 30(1)(a)",
		},
		{
			name: "dpo contact alone satisfies contact requirement",
			mutate: func(d *Declarations) {
				d.Controller.Contact = ""
			},
			wantWarnings: 0,
		},
		{
			name: "missing both contacts warns once",
			mutate: func(d *Declarations) {
				d.Controller.Contact = ""
				d.Controller.DPOContact = ""
			},
			wantWarnings: 1,
			wantContains: "contact or dpo_contact",
		},
		{
			name:         "missing purposes",
			mutate:       func(d *Declarations) { d.Processing.Purposes = nil },
			wantWarnings: 1,
			wantContains: "purposes",
		},
		{
			name:         "missing retention",
			mutate:       func(d *Declarations) { d.Processing.RetentionPeriod = "" },
			wantWarnings: 1,
			wantContains: "retention_period",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := fullDeclarations()
			tt.mutate(&d)
			warnings := d.ValidateForRoPA()
			assert.Len(t, warnings, tt.wantWarnings)
			if tt.wantContains != "" {
				assert.Contains(t, joinAll(warnings), tt.wantContains)
			}
		})
	}
}

func TestValidateForAnnexIV(t *testing.T) {
	tests := []struct {
		name         string
		mutate       func(*Declarations)
		wantWarnings int
		wantContains string
	}{
		{
			name:         "complete declarations produce no warnings",
			mutate:       func(*Declarations) {},
			wantWarnings: 0,
		},
		{
			name:         "zero value warns on all expected fields",
			mutate:       func(d *Declarations) { *d = Declarations{} },
			wantWarnings: 3,
			wantContains: "system_description",
		},
		{
			name:         "missing oversight description",
			mutate:       func(d *Declarations) { d.System.OversightDescription = "" },
			wantWarnings: 1,
			wantContains: "Art. 14",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := fullDeclarations()
			tt.mutate(&d)
			warnings := d.ValidateForAnnexIV()
			assert.Len(t, warnings, tt.wantWarnings)
			if tt.wantContains != "" {
				assert.Contains(t, joinAll(warnings), tt.wantContains)
			}
		})
	}
}

func TestMergeAgentDeclarations(t *testing.T) {
	agent := &AgentDeclarations{
		Processing: &ProcessingDeclarations{
			Purposes:        []string{"agent purpose"},
			RetentionPeriod: "30 days",
		},
		System: &SystemDeclarations{
			SystemDescription: "agent system description",
		},
	}

	t.Run("nil agent block is a no-op", func(t *testing.T) {
		d := fullDeclarations()
		merged := d.MergeAgentDeclarations(nil)
		assert.Equal(t, d, merged)
	})

	t.Run("agent values fill empty fields", func(t *testing.T) {
		d := Declarations{Controller: ControllerDeclarations{Name: "Example GmbH"}}
		merged := d.MergeAgentDeclarations(agent)
		assert.Equal(t, []string{"agent purpose"}, merged.Processing.Purposes)
		assert.Equal(t, "30 days", merged.Processing.RetentionPeriod)
		assert.Equal(t, "agent system description", merged.System.SystemDescription)
		assert.Equal(t, "Example GmbH", merged.Controller.Name, "controller untouched")
	})

	t.Run("existing values win over agent values", func(t *testing.T) {
		d := fullDeclarations()
		merged := d.MergeAgentDeclarations(agent)
		assert.Equal(t, []string{"customer support triage"}, merged.Processing.Purposes)
		assert.Equal(t, "90 days", merged.Processing.RetentionPeriod)
		assert.Equal(t, "LLM assistant for support ticket triage", merged.System.SystemDescription)
	})
}

func joinAll(list []string) string {
	out := ""
	for _, s := range list {
		out += s + "\n"
	}
	return out
}
