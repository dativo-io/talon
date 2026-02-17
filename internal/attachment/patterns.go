package attachment

import (
	"regexp"
)

// InjectionPattern detects prompt injection attempts in attachment content.
type InjectionPattern struct {
	Name        string
	Description string
	Pattern     *regexp.Regexp
	Severity    int // 1-3
}

// InjectionPatterns contains regex patterns for detecting prompt injection attempts.
var InjectionPatterns = []InjectionPattern{
	// Imperative override attempts
	{
		Name:        "Ignore Instructions",
		Description: "Attempts to override previous instructions",
		Pattern:     regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(?:(?:previous|all|prior|earlier|the|my|your)\s+){1,3}(instructions?|prompts?|rules?|directives?)`),
		Severity:    3,
	},
	{
		Name:        "New Instructions",
		Description: "Introduces replacement instructions",
		Pattern:     regexp.MustCompile(`(?i)(new|updated|revised|replacement)\s+(instructions?|prompts?|rules?|directives?)`),
		Severity:    3,
	},

	// Role-playing attempts
	{
		Name:        "Role Override",
		Description: "Attempts to change AI's role",
		Pattern:     regexp.MustCompile(`(?i)(you are now|act as|pretend to be|assume the role|behave like)\s+(a|an)?\s*\w+`),
		Severity:    2,
	},
	{
		Name:        "System Prompt",
		Description: "References system prompt",
		Pattern:     regexp.MustCompile(`(?i)system\s+(prompt|message|instruction)`),
		Severity:    2,
	},

	// Direct overrides
	{
		Name:        "Override Keyword",
		Description: "Contains 'override' in command context",
		Pattern:     regexp.MustCompile(`(?i)override\s+(security|policy|restrictions?|rules?)`),
		Severity:    3,
	},
	{
		Name:        "Bypass Attempt",
		Description: "Attempts to bypass restrictions",
		Pattern:     regexp.MustCompile(`(?i)(bypass|circumvent|evade|workaround)\s+(security|restrictions?|policies)`),
		Severity:    3,
	},

	// Encoded payloads
	{
		Name:        "Base64 Encoded",
		Description: "Suspicious base64 strings",
		Pattern:     regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`),
		Severity:    1,
	},
	{
		Name:        "Hex Encoded",
		Description: "Long hex strings",
		Pattern:     regexp.MustCompile(`0x[0-9a-fA-F]{32,}`),
		Severity:    1,
	},

	// Hidden content
	{
		Name:        "HTML Comments",
		Description: "Hidden instructions in HTML comments",
		Pattern:     regexp.MustCompile(`<!--.*?(ignore|override|system).*?-->`),
		Severity:    2,
	},
	{
		Name:        "Zero-Width Characters",
		Description: "Unicode zero-width characters",
		Pattern:     regexp.MustCompile("[\u200B\u200C\u200D\uFEFF]{3,}"),
		Severity:    2,
	},
}
