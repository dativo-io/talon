package classifier

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:gocyclo // explicit parity mirror of scan validation pipeline
func scanLegacyWithoutNormalization(s *Scanner, text string) *Classification {
	result := &Classification{
		HasPII:   false,
		Entities: []PIIEntity{},
		Tier:     0,
	}

	for i := range s.patterns {
		pattern := &s.patterns[i]
		matches := pattern.Pattern.FindAllStringIndex(text, -1)
		for _, match := range matches {
			value := text[match[0]:match[1]]

			if pattern.ValidateIBAN {
				clean := strings.ReplaceAll(value, " ", "")
				if !validateIBANLength(clean) || !validateIBANChecksum(clean) {
					continue
				}
			}
			if pattern.ValidateLuhn {
				if !luhnValid(stripNonDigits(value)) {
					continue
				}
			}
			if pattern.ValidateBSN {
				if !validateBSN(stripNonDigits(value)) {
					continue
				}
			}
			if pattern.ValidatePESEL {
				if !validatePESEL(stripNonDigits(value)) {
					continue
				}
			}
			if pattern.ValidateDNI && !validateDNI(value) {
				continue
			}
			if pattern.ValidateNIE && !validateNIE(value) {
				continue
			}
			if pattern.ValidateNIF && !validateNIF(value) {
				continue
			}
			if pattern.ValidateIPv4 && !validateIPv4(value) {
				continue
			}

			confidence := enhanceScoreWithContext(text, match[0], pattern.Score, pattern.ContextWords)
			if confidence < s.minScore {
				continue
			}

			result.Entities = append(result.Entities, PIIEntity{
				Type:        pattern.Type,
				Value:       value,
				Position:    match[0],
				Confidence:  confidence,
				Sensitivity: pattern.Sensitivity,
			})
		}
	}

	result.HasPII = len(result.Entities) > 0
	result.Tier = s.determineTier(result.Entities)
	return result
}

func TestBuiltInScannerNormalizationParity(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	tests := []string{
		"Email user@example.com and IBAN DE89370400440532013000",
		"Passport number AB1234567 issued in Berlin",
		"Customer Mrs Smith lives in Berlin and has NIF 123456789",
		"Server at 192.168.1.100 and NI number AB123456C",
		"DNI 12345678Z and NIE X1234567L",
	}

	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			legacy := scanLegacyWithoutNormalization(scanner, text)
			current := scanner.Scan(ctx, text)

			require.Equal(t, legacy.HasPII, current.HasPII)
			require.Equal(t, legacy.Tier, current.Tier)
			require.Len(t, current.Entities, len(legacy.Entities))
			for i := range legacy.Entities {
				assert.Equal(t, legacy.Entities[i].Type, current.Entities[i].Type)
				assert.Equal(t, legacy.Entities[i].Value, current.Entities[i].Value)
				assert.Equal(t, legacy.Entities[i].Position, current.Entities[i].Position)
				assert.Equal(t, legacy.Entities[i].Sensitivity, current.Entities[i].Sensitivity)
				assert.InDelta(t, legacy.Entities[i].Confidence, current.Entities[i].Confidence, 0.00001)
			}
		})
	}
}
