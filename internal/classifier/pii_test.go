package classifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPIIDetection(t *testing.T) {
	scanner := NewScanner()
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
			text:      "Card: 5111111111111111",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"credit_card"},
		},
		{
			name:     "german VAT",
			text:     "VAT ID: DE123456789",
			wantPII:  true,
			wantTier: 2, // IBAN pattern also matches (DE + digits), sensitivity 3
			wantTypes: []string{"vat_id"},
		},
		{
			name:     "french VAT",
			text:     "TVA: FR12345678901",
			wantPII:  true,
			wantTier: 2, // IBAN pattern also matches (FR + digits), sensitivity 3
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
			name:     "IPv4 address",
			text:     "Server at 192.168.1.100",
			wantPII:  true,
			wantTier: 2, // Phone pattern also matches numeric octets, >3 entities
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
			name:     "empty text",
			text:     "",
			wantPII:  false,
			wantTier: 0,
		},
		{
			name:      "many low-sensitivity entities bump to tier 2",
			text:      "a@b.com c@d.com e@f.com g@h.com",
			wantPII:   true,
			wantTier:  2,
			wantTypes: []string{"email"},
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
	scanner := NewScanner()
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
			wantContains: []string{"[EMAIL]"},
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
	scanner := NewScanner()

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
				{Type: "email"},
			},
			wantTier: 1,
		},
		{
			name: "credit card always tier 2",
			entities: []PIIEntity{
				{Type: "credit_card"},
			},
			wantTier: 2,
		},
		{
			name: "SSN always tier 2",
			entities: []PIIEntity{
				{Type: "ssn"},
			},
			wantTier: 2,
		},
		{
			name: "IBAN always tier 2",
			entities: []PIIEntity{
				{Type: "iban"},
			},
			wantTier: 2,
		},
		{
			name: "4+ low sensitivity entities bump to tier 2",
			entities: []PIIEntity{
				{Type: "email"},
				{Type: "email"},
				{Type: "email"},
				{Type: "email"},
			},
			wantTier: 2,
		},
		{
			name: "3 low sensitivity entities stay at tier 1",
			entities: []PIIEntity{
				{Type: "email"},
				{Type: "ip_address"},
				{Type: "phone"},
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
	scanner := NewScanner()
	require.NotNil(t, scanner)
	assert.Greater(t, len(scanner.patterns), 0, "scanner should have patterns loaded")
}
