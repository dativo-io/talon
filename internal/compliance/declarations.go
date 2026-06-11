package compliance

import "fmt"

// Declared compliance metadata: business facts that auditor exports (RoPA,
// Annex IV) require but that cannot be derived from runtime evidence — who
// the controller is, why data is processed, how long it is retained.
//
// Operators declare these once:
//   - Controller identity: talon.config.yaml `compliance.controller`
//     (org-level, owned by the DevOps/platform team together with the DPO).
//   - Processing and system declarations: agent.talon.yaml
//     `compliance.declarations` (per-agent, owned by governance/compliance).
//
// Generators merge declared facts with evidence-derived facts at render
// time. Missing declarations are reported as warnings and rendered as
// flagged placeholder sections — never hard failures — so exports work out
// of the box and tell the DPO exactly what to fill in.

// ControllerDeclarations identifies the data controller for GDPR Art. 30(1)(a).
// Declared in talon.config.yaml under `compliance.controller`.
type ControllerDeclarations struct {
	// Name is the legal name of the controller organization.
	Name string `yaml:"name,omitempty" json:"name,omitempty" mapstructure:"name"`
	// Contact is a general contact point (email or address) for the controller.
	Contact string `yaml:"contact,omitempty" json:"contact,omitempty" mapstructure:"contact"`
	// DPOContact is the Data Protection Officer contact, where designated.
	DPOContact string `yaml:"dpo_contact,omitempty" json:"dpo_contact,omitempty" mapstructure:"dpo_contact"`
	// Address is the registered address of the controller.
	Address string `yaml:"address,omitempty" json:"address,omitempty" mapstructure:"address"`
	// Representative is the EU representative, where applicable (GDPR Art. 27).
	Representative string `yaml:"representative,omitempty" json:"representative,omitempty" mapstructure:"representative"`
}

// ProcessingDeclarations holds the per-agent declared facts for GDPR
// Art. 30(1) processing records. Declared in agent.talon.yaml under
// `compliance.declarations.processing`.
type ProcessingDeclarations struct {
	// Purposes of processing (Art. 30(1)(b)), e.g. "customer support triage".
	Purposes []string `yaml:"purposes,omitempty" json:"purposes,omitempty" mapstructure:"purposes"`
	// DataSubjectCategories (Art. 30(1)(c)), e.g. "customers", "employees".
	DataSubjectCategories []string `yaml:"data_subject_categories,omitempty" json:"data_subject_categories,omitempty" mapstructure:"data_subject_categories"`
	// PersonalDataCategories (Art. 30(1)(c)) declared by the operator;
	// merged with PII entity types observed in evidence at render time.
	PersonalDataCategories []string `yaml:"personal_data_categories,omitempty" json:"personal_data_categories,omitempty" mapstructure:"personal_data_categories"`
	// RetentionPeriod is the envisaged erasure time limit (Art. 30(1)(f)),
	// e.g. "90 days" or "duration of contract + 1 year".
	RetentionPeriod string `yaml:"retention_period,omitempty" json:"retention_period,omitempty" mapstructure:"retention_period"`
	// Safeguards describes organisational measures beyond Talon's built-in
	// technical controls (Art. 30(1)(g)).
	Safeguards string `yaml:"safeguards,omitempty" json:"safeguards,omitempty" mapstructure:"safeguards"`
	// LegalBasis is the lawful basis relied upon (Art. 6), e.g. "contract".
	LegalBasis string `yaml:"legal_basis,omitempty" json:"legal_basis,omitempty" mapstructure:"legal_basis"`
}

// SystemDeclarations holds the per-agent declared facts used by the EU AI Act
// Annex IV technical-documentation pack. Declared in agent.talon.yaml under
// `compliance.declarations.system`.
type SystemDeclarations struct {
	// SystemDescription is a general description of the AI system and how
	// it is used in the organization (Annex IV s.1).
	SystemDescription string `yaml:"system_description,omitempty" json:"system_description,omitempty" mapstructure:"system_description"`
	// IntendedPurpose states what the system is intended to be used for.
	IntendedPurpose string `yaml:"intended_purpose,omitempty" json:"intended_purpose,omitempty" mapstructure:"intended_purpose"`
	// OversightDescription describes the human-oversight arrangements
	// beyond Talon's plan-review/approval gates (Art. 14).
	OversightDescription string `yaml:"oversight_description,omitempty" json:"oversight_description,omitempty" mapstructure:"oversight_description"`
}

// AgentDeclarations is the `compliance.declarations` block in agent.talon.yaml.
type AgentDeclarations struct {
	Processing *ProcessingDeclarations `yaml:"processing,omitempty" json:"processing,omitempty" mapstructure:"processing"`
	System     *SystemDeclarations     `yaml:"system,omitempty" json:"system,omitempty" mapstructure:"system"`
}

// Declarations aggregates the declared facts from operator config and agent
// policy for one export. Zero value is valid: generators render flagged
// placeholders for anything missing.
type Declarations struct {
	Controller ControllerDeclarations `json:"controller"`
	Processing ProcessingDeclarations `json:"processing"`
	System     SystemDeclarations     `json:"system"`
}

// MergeAgentDeclarations folds a per-agent declarations block (may be nil)
// into d, returning the result. Agent values fill empty fields only.
func (d Declarations) MergeAgentDeclarations(agent *AgentDeclarations) Declarations {
	if agent == nil {
		return d
	}
	if agent.Processing != nil {
		if len(d.Processing.Purposes) == 0 {
			d.Processing.Purposes = agent.Processing.Purposes
		}
		if len(d.Processing.DataSubjectCategories) == 0 {
			d.Processing.DataSubjectCategories = agent.Processing.DataSubjectCategories
		}
		if len(d.Processing.PersonalDataCategories) == 0 {
			d.Processing.PersonalDataCategories = agent.Processing.PersonalDataCategories
		}
		if d.Processing.RetentionPeriod == "" {
			d.Processing.RetentionPeriod = agent.Processing.RetentionPeriod
		}
		if d.Processing.Safeguards == "" {
			d.Processing.Safeguards = agent.Processing.Safeguards
		}
		if d.Processing.LegalBasis == "" {
			d.Processing.LegalBasis = agent.Processing.LegalBasis
		}
	}
	if agent.System != nil {
		if d.System.SystemDescription == "" {
			d.System.SystemDescription = agent.System.SystemDescription
		}
		if d.System.IntendedPurpose == "" {
			d.System.IntendedPurpose = agent.System.IntendedPurpose
		}
		if d.System.OversightDescription == "" {
			d.System.OversightDescription = agent.System.OversightDescription
		}
	}
	return d
}

// ValidateForRoPA returns human-readable warnings for declared fields a GDPR
// Art. 30 RoPA expects. An empty slice means all expected fields are set.
func (d Declarations) ValidateForRoPA() []string {
	var warnings []string
	if d.Controller.Name == "" {
		warnings = append(warnings, missingDecl("compliance.controller.name (talon.config.yaml)", "controller identity, GDPR Art. 30(1)(a)"))
	}
	if d.Controller.Contact == "" && d.Controller.DPOContact == "" {
		warnings = append(warnings, missingDecl("compliance.controller.contact or dpo_contact (talon.config.yaml)", "controller contact details, GDPR Art. 30(1)(a)"))
	}
	if len(d.Processing.Purposes) == 0 {
		warnings = append(warnings, missingDecl("compliance.declarations.processing.purposes (agent.talon.yaml)", "purposes of processing, GDPR Art. 30(1)(b)"))
	}
	if len(d.Processing.DataSubjectCategories) == 0 {
		warnings = append(warnings, missingDecl("compliance.declarations.processing.data_subject_categories (agent.talon.yaml)", "categories of data subjects, GDPR Art. 30(1)(c)"))
	}
	if d.Processing.RetentionPeriod == "" {
		warnings = append(warnings, missingDecl("compliance.declarations.processing.retention_period (agent.talon.yaml)", "envisaged erasure time limits, GDPR Art. 30(1)(f)"))
	}
	return warnings
}

// ValidateForAnnexIV returns human-readable warnings for declared fields the
// EU AI Act Annex IV technical-documentation pack expects.
func (d Declarations) ValidateForAnnexIV() []string {
	var warnings []string
	if d.System.SystemDescription == "" {
		warnings = append(warnings, missingDecl("compliance.declarations.system.system_description (agent.talon.yaml)", "general system description, EU AI Act Annex IV s.1"))
	}
	if d.System.IntendedPurpose == "" {
		warnings = append(warnings, missingDecl("compliance.declarations.system.intended_purpose (agent.talon.yaml)", "intended purpose, EU AI Act Annex IV s.1"))
	}
	if d.System.OversightDescription == "" {
		warnings = append(warnings, missingDecl("compliance.declarations.system.oversight_description (agent.talon.yaml)", "human-oversight arrangements, EU AI Act Art. 14"))
	}
	return warnings
}

func missingDecl(field, supports string) string {
	return fmt.Sprintf("declaration missing: set %s — needed for %s", field, supports)
}
