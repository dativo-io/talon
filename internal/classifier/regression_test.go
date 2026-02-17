package classifier

// Regression tests for PR #7 review findings.
// Each test is named after the bug it catches.
// These tests document known bugs that were fixed in PROMPT_03_FIX.
// They guard against reintroduction of these bugs in future changes.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// BUG-1: Phone regex `\+?[1-9]\d{1,14}` had optional + prefix.
// IPv4 addresses like 192.168.1.100 produced 4 false phone matches,
// pushing the result to Tier 2 via the "4+ entities" rule.
// Fix: require mandatory + prefix, minimum 7 digits: `\+[1-9]\d{6,14}\b`
func TestBug1_PhoneRegexFalsePositiveOnIPv4(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	// An IPv4 address contains no phone numbers.
	// BROKEN BEHAVIOUR: Tier 2 because octets match phone regex 4 times.
	// CORRECT BEHAVIOUR: Tier 1 (ip_address is sensitivity 1, 1 entity → Tier 1).
	result := scanner.Scan(ctx, "Server at 192.168.1.100")

	assert.True(t, result.HasPII, "IPv4 is PII (ip_address type)")

	for _, e := range result.Entities {
		assert.NotEqual(t, "phone", e.Type,
			"BUG-1: IPv4 octets must NOT be detected as phone numbers, got entity: %+v", e)
	}

	assert.Equal(t, 1, result.Tier,
		"BUG-1: IPv4 only → ip_address (sensitivity 1) → Tier 1, not Tier 2")
}

// BUG-1b: Numeric business values also false-positive as phone numbers.
// "€2.3M revenue" contains digits that match the broken phone pattern.
func TestBug1b_PhoneRegexFalsePositiveOnBusinessNumbers(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	result := scanner.Scan(ctx, "Q4 revenue was 2300000 EUR, growth 15 percent")

	for _, e := range result.Entities {
		assert.NotEqual(t, "phone", e.Type,
			"BUG-1b: plain business numbers must NOT match phone pattern, got entity: %+v", e)
	}

	assert.False(t, result.HasPII,
		"BUG-1b: plain business text with no PII must not be classified as PII")
	assert.Equal(t, 0, result.Tier,
		"BUG-1b: plain business text must be Tier 0")
}

// BUG-1c: A valid E.164 phone number WITH + prefix must still be detected.
// (Guard against over-correcting the fix.)
func TestBug1c_ValidE164PhoneIsDetected(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	result := scanner.Scan(ctx, "Call us at +4930123456789")

	assert.True(t, result.HasPII, "BUG-1c: E.164 phone +4930123456789 must be detected")

	found := false
	for _, e := range result.Entities {
		if e.Type == "phone" {
			found = true
		}
	}
	assert.True(t, found, "BUG-1c: phone entity must be present for E.164 number")
}

// BUG-2: IBAN regex `\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b` matches VAT IDs.
// DE123456789 (11 chars) is a German VAT ID, not an IBAN.
// German IBANs are exactly 22 chars. Without length + MOD-97 validation,
// the VAT ID was misclassified as sensitivity-3 IBAN → Tier 2.
// Fix: add ISO 13616 MOD-97 checksum + country-specific exact length validation.
func TestBug2_IBANRegexMatchesGermanVATID(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	// DE123456789 is a German VAT ID format (9 digits after DE).
	// It is NOT a valid IBAN — German IBANs are 22 chars (DE + 2 check + 18 BBAN).
	// BROKEN BEHAVIOUR: classified as IBAN (sensitivity 3) → Tier 2.
	// CORRECT BEHAVIOUR: classified as vat_id (sensitivity 1) → Tier 1.
	result := scanner.Scan(ctx, "VAT ID: DE123456789")

	for _, e := range result.Entities {
		assert.NotEqual(t, "iban", e.Type,
			"BUG-2: DE123456789 is a VAT ID (11 chars), not a German IBAN (22 chars), got entity: %+v", e)
	}

	assert.Equal(t, 1, result.Tier,
		"BUG-2: German VAT ID → vat_id (sensitivity 1) → Tier 1, not Tier 2")
}

// BUG-2b: French VAT ID also incorrectly classified as IBAN.
func TestBug2b_IBANRegexMatchesFrenchVATID(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	// FR12345678901 is a French VAT ID (13 chars).
	// French IBANs are 27 chars. This must NOT match as IBAN.
	result := scanner.Scan(ctx, "TVA: FR12345678901")

	for _, e := range result.Entities {
		assert.NotEqual(t, "iban", e.Type,
			"BUG-2b: FR12345678901 is a VAT ID, not a French IBAN (27 chars), got entity: %+v", e)
	}

	assert.Equal(t, 1, result.Tier,
		"BUG-2b: French VAT ID must be Tier 1, not Tier 2")
}

// BUG-2c: A genuine German IBAN must still be detected after the fix.
// DE89370400440532013000 is a valid 22-char IBAN with correct MOD-97 checksum.
func TestBug2c_ValidGermanIBANIsDetected(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	result := scanner.Scan(ctx, "Pay to DE89370400440532013000")

	assert.True(t, result.HasPII, "BUG-2c: valid German IBAN must be detected")

	found := false
	for _, e := range result.Entities {
		if e.Type == "iban" {
			found = true
			assert.Equal(t, "DE89370400440532013000", e.Value)
		}
	}
	assert.True(t, found, "BUG-2c: iban entity must be present for valid German IBAN")
	assert.Equal(t, 2, result.Tier, "BUG-2c: valid IBAN → Tier 2")
}

// BUG-3: Passport number pattern `\b[A-Z]{1,2}\d{6,9}\b` fired without
// any context words. It matched regulation codes, model version strings,
// EU directives, and any alphanumeric identifier.
// Fix: Presidio-style context scoring — base score 0.4, context boost +0.35,
// minScore 0.5 → without context words the match is discarded.
func TestBug3_PassportPatternMatchesRegulationCodes(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	// GDPR2016/679 — EU regulation reference, NOT a passport number.
	// EU123456 — generic alphanumeric ID, NOT a passport number.
	// AB1234567 alone — ambiguous, should not fire without context.
	texts := []struct {
		text string
		desc string
	}{
		{"See regulation EU123456 for details", "EU regulation code"},
		{"Reference number: AB1234567 from order system", "generic order reference without passport context"},
		{"Model version V1234567 released", "software version string"},
	}

	for _, tc := range texts {
		result := scanner.Scan(ctx, tc.text)
		for _, e := range result.Entities {
			assert.NotEqual(t, "passport", e.Type,
				"BUG-3: %s must NOT be detected as passport number, got entity: %+v", tc.desc, e)
		}
	}
}

// BUG-3b: A real passport number WITH context words must still be detected.
func TestBug3b_PassportWithContextIsDetected(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	result := scanner.Scan(ctx, "Passport number: AB1234567 issued in Berlin")

	assert.True(t, result.HasPII, "BUG-3b: passport with context must be detected")

	found := false
	for _, e := range result.Entities {
		if e.Type == "passport" {
			found = true
		}
	}
	assert.True(t, found, "BUG-3b: passport entity must be present when context word present")
	assert.Equal(t, 2, result.Tier, "BUG-3b: passport → Tier 2")
}

// BUG-4: determineTier() did not include "passport" in the high-sensitivity list.
// The original implementation only checked: credit_card, ssn, iban by type name.
// A passport entity therefore fell through to the entity-count heuristic.
// Fix: determineTier now uses Sensitivity field (>= 2 → Tier 2), making it
// work for passport and any custom recognizer with high sensitivity.
func TestBug4_PassportNotInHighSensitivityList(t *testing.T) {
	scanner := MustNewScanner()

	// Directly test determineTier with a passport entity.
	// This isolates the determineTier bug from the pattern-matching bug (BUG-3).
	entities := []PIIEntity{
		{Type: "passport", Value: "AB1234567", Confidence: 0.95, Sensitivity: 3},
	}

	tier := scanner.determineTier(entities)

	assert.Equal(t, 2, tier,
		"BUG-4: passport entity (sensitivity 3) must always result in Tier 2, got Tier %d", tier)
}

// BUG-4b: determineTier must also work for arbitrary custom recognizers.
// Any entity with Sensitivity >= 2 must yield Tier 2.
func TestBug4b_CustomRecognizerHighSensitivityYieldsTier2(t *testing.T) {
	scanner := MustNewScanner()

	entities := []PIIEntity{
		{Type: "employee_id", Value: "EMP-123456", Confidence: 0.95, Sensitivity: 2},
	}

	tier := scanner.determineTier(entities)

	assert.Equal(t, 2, tier,
		"BUG-4b: custom entity with sensitivity 2 must yield Tier 2")
}

// BUG-5: Credit card pattern accepted numbers that fail the Luhn checksum.
// 4999999999999999 matches the Visa prefix pattern but is not a valid card number.
// Without Luhn validation, this produced a false positive.
// Fix: add ValidateLuhn flag + luhnValid() gate in Scan().
func TestBug5_CreditCardWithoutLuhnValidation(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	// 4999999999999999 — valid Visa prefix (4xxx), correct length (16 digits),
	// but FAILS the Luhn checksum. Not a real card number.
	result := scanner.Scan(ctx, "Card number 4999999999999999")

	for _, e := range result.Entities {
		assert.NotEqual(t, "credit_card", e.Type,
			"BUG-5: 4999999999999999 fails Luhn checksum, must NOT be detected as credit card, got entity: %+v", e)
	}
}

// BUG-5b: A valid card number (passes Luhn) must still be detected.
// 4111111111111111 is the canonical Luhn-valid Visa test number.
func TestBug5b_ValidCreditCardIsDetected(t *testing.T) {
	scanner := MustNewScanner()
	ctx := context.Background()

	result := scanner.Scan(ctx, "Card: 4111111111111111")

	assert.True(t, result.HasPII, "BUG-5b: Luhn-valid Visa test card must be detected")

	found := false
	for _, e := range result.Entities {
		if e.Type == "credit_card" {
			found = true
		}
	}
	assert.True(t, found, "BUG-5b: credit_card entity must be present for Luhn-valid number")
}
