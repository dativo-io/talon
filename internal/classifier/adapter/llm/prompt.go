// Package llm implements a classifier.Facade backed by an OpenAI-compatible
// chat endpoint (Ollama, llama.cpp server, vLLM) prompted for NER.
//
// LLMs are unreliable at reporting character offsets, so this adapter never
// trusts them: the model returns entity type + verbatim value, and Talon
// locates every occurrence of the value in the original text itself
// (deterministic byte offsets). Values that do not appear verbatim in the
// text are dropped as hallucinations. Like every external engine, failures
// are fail-closed on enforcement paths.
package llm

import (
	"fmt"
	"strings"
)

// PromptVersion identifies the built-in NER prompt. It is recorded in
// evidence as the engine version so detections are attributable to the exact
// prompt semantics that produced them. The prompt is intentionally NOT
// operator-customizable; custom prompting belongs behind the generic adapter
// protocol where the engine owns its own semantics.
const PromptVersion = "llm-ner/v1"

// entityDescriptions gives the model one-line definitions for well-known
// entity labels. Unknown labels fall back to the label itself.
var entityDescriptions = map[string]string{
	"EMAIL_ADDRESS":   "email addresses",
	"PHONE_NUMBER":    "telephone numbers in any format",
	"IBAN":            "IBAN bank account numbers",
	"IBAN_CODE":       "IBAN bank account numbers",
	"CREDIT_CARD":     "payment card numbers",
	"EU_VAT_ID":       "EU VAT identification numbers",
	"DE_SSN":          "German social insurance numbers",
	"UK_NINO":         "UK National Insurance numbers",
	"FR_INSEE":        "French INSEE/NIR social security numbers",
	"FR_NIR":          "French NIR social security numbers",
	"IP_ADDRESS":      "IPv4 or IPv6 addresses",
	"PASSPORT":        "passport numbers",
	"DE_ID_CARD":      "German identity card numbers",
	"DE_TAX_ID":       "German tax identification numbers",
	"NL_BSN":          "Dutch citizen service (BSN) numbers",
	"PL_PESEL":        "Polish PESEL numbers",
	"ES_DNI":          "Spanish DNI numbers",
	"ES_NIE":          "Spanish NIE numbers",
	"PT_NIF":          "Portuguese NIF numbers",
	"PERSON":          "personal names of real people",
	"LOCATION":        "physical addresses or specific locations tied to a person",
	"US_SSN":          "US social security numbers",
	"DATE_OF_BIRTH":   "dates of birth",
	"MEDICAL_LICENSE": "medical license numbers",
}

// BuildSystemPrompt renders the versioned NER instruction for the given
// entity labels (Presidio-style, derived from the effective policy).
func BuildSystemPrompt(entityTypes []string) string {
	var b strings.Builder
	b.WriteString("You are a strict PII detector. Find every occurrence of the following entity types in the user's text:\n\n")
	for _, e := range entityTypes {
		desc := entityDescriptions[e]
		if desc == "" {
			desc = strings.ToLower(strings.ReplaceAll(e, "_", " "))
		}
		fmt.Fprintf(&b, "- %s: %s\n", e, desc)
	}
	b.WriteString(`
Respond with ONLY a JSON object of this exact shape, no prose:
{"entities":[{"type":"<ENTITY_TYPE>","value":"<verbatim substring>"}]}

Rules:
- "value" MUST be copied character-for-character from the text, including case, spacing, and punctuation. Never paraphrase, normalize, or truncate.
- Report each distinct value once even if it appears multiple times.
- Only use the entity types listed above.
- Do NOT report redaction placeholders such as [EMAIL], [PHONE], or <PII .../> tags — they are already redacted.
- If nothing is found, respond with {"entities":[]}.`)
	return b.String()
}
