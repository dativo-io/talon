package classifier

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPIIDetection(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	tests := []struct {
		name      string
		text      string
		wantPII   bool
		wantTier  int
		wantTypes []string
	}{
		{
			name:     "no PII",
			text:     "Hello world, this is a test",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:      "email address",
			text:      "Contact me at user@example.com",
			wantPII:   true,
			wantTier:  1,
			wantTypes: []string{"email"},
		},
		{
			name:      "IBAN",
			text:      "My IBAN is DE89370400440532013000",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"iban"},
		},
		{
			name:      "credit card visa",
			text:      "Card: 4111111111111111",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"credit_card"},
		},
		{
			name:      "credit card mastercard",
			text:      "Card: 5500000000000004",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"credit_card"},
		},
		{
			name:      "german VAT",
			text:      "VAT ID: DE123456789",
			wantPII:   true,
			wantTier:  1, // IBAN regex still matches but fails IBAN validation (wrong length/checksum), so only VAT (sensitivity 1) remains
			wantTypes: []string{"vat_id"},
		},
		{
			name:      "french VAT",
			text:      "TVA: FR12345678901",
			wantPII:   true,
			wantTier:  1, // Same: IBAN validation gate filters out false-positive IBAN match, VAT sensitivity is now 1
			wantTypes: []string{"vat_id"},
		},
		{
			name:      "UK national insurance",
			text:      "NI Number: AB123456C",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"ssn"},
		},
		{
			name:      "IPv4 address",
			text:      "Server at 192.168.1.100",
			wantPII:   true,
			wantTier:  1,
			wantTypes: []string{"ip_address"},
		},
		{
			name:      "multiple PII types",
			text:      "Email: test@example.com, IBAN: DE89370400440532013000",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"email", "iban"},
		},
		{
			name:      "phone E.164 german",
			text:      "Call me at +491234567890",
			wantPII:   true,
			wantTier:  1,
			wantTypes: []string{"phone"},
		},
		{
			name:      "phone E.164 french",
			text:      "Téléphone: +33123456789",
			wantPII:   true,
			wantTier:  1,
			wantTypes: []string{"phone"},
		},
		{
			name:      "phone E.164 minimum 7 digits",
			text:      "Number +1234567",
			wantPII:   true,
			wantTier:  1,
			wantTypes: []string{"phone"},
		},
		{
			name:     "plain numbers are not phone PII",
			text:     "Revenue was 2300000 EUR in 2025. Grew 15 percent.",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:     "short number with plus not phone",
			text:     "Offset +12 from baseline",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:     "empty text",
			text:     "",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:      "many low-sensitivity entities stay tier 1",
			text:      "a@b.com c@d.com e@f.com g@h.com",
			wantPII:   true,
			wantTier:  1,
			wantTypes: []string{"email"},
		},
		{
			name:      "passport with context word yields tier 2",
			text:      "Passport number: AB1234567",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"passport"},
		},
		{
			name:     "passport without context word is filtered",
			text:     "Reference code: AB1234567",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:     "invalid IBAN fails checksum gate",
			text:     "IBAN DE00000000000000000000",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:     "invalid credit card fails Luhn gate",
			text:     "Card: 4111111111111112",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:      "valid IBAN passes checksum gate",
			text:      "IBAN: DE89370400440532013000",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"iban"},
		},
		{
			name:      "passport with German context word",
			text:      "Reisepass Nr: AB1234567",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"passport"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.Scan(ctx, tt.text)

			assert.Equal(t, tt.wantPII, result.HasPII, "HasPII mismatch")
			assert.Equal(t, tt.wantTier, result.Tier, "Tier mismatch")

			if len(tt.wantTypes) > 0 {
				types := make(map[string]bool)
				for _, entity := range result.Entities {
					types[entity.Type] = true
				}
				for _, wantType := range tt.wantTypes {
					assert.True(t, types[wantType], "missing type: %s", wantType)
				}
			}
		})
	}
}

func TestPIIRedaction(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	tests := []struct {
		name         string
		text         string
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:         "redact email and IBAN",
			text:         "Email user@example.com, IBAN DE89370400440532013000",
			wantContains: []string{"[EMAIL]", "[IBAN]"},
			wantAbsent:   []string{"user@example.com", "DE89370400440532013000"},
		},
		{
			name:         "no PII unchanged",
			text:         "Hello world",
			wantContains: []string{"Hello world"},
			wantAbsent:   []string{},
		},
		{
			name:       "redact IP address",
			text:       "Server at 192.168.1.100",
			wantAbsent: []string{"192.168.1.100"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redacted := scanner.Redact(ctx, tt.text)

			for _, want := range tt.wantContains {
				assert.Contains(t, redacted, want)
			}
			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, redacted, absent)
			}
		})
	}
}

func TestDetermineTier(t *testing.T) {
	scanner := MustNewScanner()

	tests := []struct {
		name     string
		entities []PIIEntity
		wantTier int
	}{
		{
			name:     "no entities",
			entities: []PIIEntity{},
			wantTier: 0,
		},
		{
			name: "single low sensitivity",
			entities: []PIIEntity{
				{Type: "email", Sensitivity: 1},
			},
			wantTier: 1,
		},
		{
			name: "credit card sensitivity 3 yields tier 2",
			entities: []PIIEntity{
				{Type: "credit_card", Sensitivity: 3},
			},
			wantTier: 2,
		},
		{
			name: "SSN sensitivity 3 yields tier 2",
			entities: []PIIEntity{
				{Type: "ssn", Sensitivity: 3},
			},
			wantTier: 2,
		},
		{
			name: "IBAN sensitivity 3 yields tier 2",
			entities: []PIIEntity{
				{Type: "iban", Sensitivity: 3},
			},
			wantTier: 2,
		},
		{
			name: "passport sensitivity 3 yields tier 2",
			entities: []PIIEntity{
				{Type: "passport", Sensitivity: 3},
			},
			wantTier: 2,
		},
		{
			name: "custom recognizer sensitivity 2 yields tier 2",
			entities: []PIIEntity{
				{Type: "employee_id", Sensitivity: 2},
			},
			wantTier: 2,
		},
		{
			name: "4 low sensitivity entities stay tier 1",
			entities: []PIIEntity{
				{Type: "email", Sensitivity: 1},
				{Type: "email", Sensitivity: 1},
				{Type: "email", Sensitivity: 1},
				{Type: "email", Sensitivity: 1},
			},
			wantTier: 1,
		},
		{
			name: "3 low sensitivity entities stay at tier 1",
			entities: []PIIEntity{
				{Type: "email", Sensitivity: 1},
				{Type: "ip_address", Sensitivity: 1},
				{Type: "phone", Sensitivity: 1},
			},
			wantTier: 1,
		},
		{
			name: "unset sensitivity treated as 1",
			entities: []PIIEntity{
				{Type: "email", Sensitivity: 0},
			},
			wantTier: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier := scanner.determineTier(tt.entities)
			assert.Equal(t, tt.wantTier, tier)
		})
	}
}

func TestNewScanner(t *testing.T) {
	scanner, err := NewScanner()
	require.NoError(t, err)
	require.NotNil(t, scanner)
	assert.Greater(t, len(scanner.patterns), 0, "scanner should have patterns loaded")
}

func TestNewScannerWithEnabledEntities(t *testing.T) {
	scanner, err := NewScanner(WithEnabledEntities([]string{"EMAIL_ADDRESS"}))
	require.NoError(t, err)

	ctx := context.Background()
	result := scanner.Scan(ctx, "user@example.com and +491234567890")

	assert.True(t, result.HasPII, "should detect email")
	types := make(map[string]bool)
	for _, e := range result.Entities {
		types[e.Type] = true
	}
	assert.True(t, types["email"], "email should be detected")
	assert.False(t, types["phone"], "phone should be filtered out")
}

func TestNewScannerWithDisabledEntities(t *testing.T) {
	scanner, err := NewScanner(WithDisabledEntities([]string{"IP_ADDRESS", "PASSPORT"}))
	require.NoError(t, err)

	ctx := context.Background()
	result := scanner.Scan(ctx, "Server at 192.168.1.100")

	assert.False(t, result.HasPII, "IP should be filtered out")
	assert.Empty(t, result.Entities)
}

func TestNewScannerWithCustomRecognizers(t *testing.T) {
	score095 := 0.95
	custom := []RecognizerConfig{
		{
			Name:            "Employee ID",
			SupportedEntity: "EMPLOYEE_ID",
			Patterns: []PatternConfig{
				{Name: "emp id", Regex: `\bEMP-\d{6}\b`, Score: &score095},
			},
			Sensitivity: 2,
		},
	}

	scanner, err := NewScanner(WithCustomRecognizers(custom))
	require.NoError(t, err)

	ctx := context.Background()
	result := scanner.Scan(ctx, "Contact EMP-123456 for details")

	assert.True(t, result.HasPII)
	assert.Equal(t, 2, result.Tier, "custom recognizer with sensitivity 2 should yield tier 2")
	found := false
	for _, e := range result.Entities {
		if e.Type == "employee_id" && e.Value == "EMP-123456" {
			found = true
		}
	}
	assert.True(t, found, "custom employee ID pattern should match")
}

// TestNewScannerWithCustomRecognizersOmittedScore verifies that when score is
// omitted (nil), CompilePIIPatterns uses DefaultMinScore so custom patterns
// are not filtered out by the scanner's minScore threshold.
func TestNewScannerWithCustomRecognizersOmittedScore(t *testing.T) {
	custom := []RecognizerConfig{
		{
			Name:            "Ticket ID",
			SupportedEntity: "TICKET_ID",
			Patterns: []PatternConfig{
				{Name: "ticket", Regex: `\bTKT-\d{5}\b`, Score: nil}, // omitted score
			},
			Sensitivity: 1,
		},
	}

	scanner, err := NewScanner(WithCustomRecognizers(custom))
	require.NoError(t, err)

	ctx := context.Background()
	result := scanner.Scan(ctx, "See TKT-12345 for details")

	assert.True(t, result.HasPII, "custom pattern with omitted score should match")
	found := false
	for _, e := range result.Entities {
		if e.Type == "ticket_id" && e.Value == "TKT-12345" {
			found = true
			assert.GreaterOrEqual(t, e.Confidence, 0.5, "confidence should be at least DefaultMinScore")
		}
	}
	assert.True(t, found, "ticket_id entity should be present when score is omitted")
}

func TestNewScannerWithPatternFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom_patterns.yaml")
	yaml := `
recognizers:
  - name: "Project Code"
    supported_entity: "PROJECT_CODE"
    patterns:
      - name: "project code"
        regex: '\bPROJ-[A-Z]{3}-\d{4}\b'
        score: 0.9
    sensitivity: 1
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	scanner, err := NewScanner(WithPatternFile(path))
	require.NoError(t, err)

	ctx := context.Background()
	result := scanner.Scan(ctx, "Working on PROJ-ABC-1234")

	assert.True(t, result.HasPII)
	found := false
	for _, e := range result.Entities {
		if e.Type == "project_code" {
			found = true
		}
	}
	assert.True(t, found, "pattern file recognizer should be loaded")
}

func TestNewScannerWithMissingPatternFile(t *testing.T) {
	scanner, err := NewScanner(WithPatternFile("/nonexistent/patterns.yaml"))
	require.NoError(t, err, "missing pattern file should be silently skipped")
	require.NotNil(t, scanner)
	assert.Greater(t, len(scanner.patterns), 0, "should still have defaults")
}

func TestNewScannerBackwardCompatibility(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	result := scanner.Scan(ctx, "Email user@example.com, IBAN DE89370400440532013000")
	assert.True(t, result.HasPII)
	assert.Equal(t, 2, result.Tier)

	types := make(map[string]bool)
	for _, e := range result.Entities {
		types[e.Type] = true
	}
	assert.True(t, types["email"])
	assert.True(t, types["iban"])
}
