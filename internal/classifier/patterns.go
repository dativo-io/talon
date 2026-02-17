package classifier

import (
	"regexp"
)

// PIIPattern represents a detectable PII pattern.
type PIIPattern struct {
	Name        string
	Type        string
	Pattern     *regexp.Regexp
	Countries   []string
	Sensitivity int // 1-3, higher = more sensitive
}

// EUPatterns contains regex patterns for EU PII detection across 27 member states.
var EUPatterns = []PIIPattern{
	// Email (universal)
	{
		Name:        "Email Address",
		Type:        "email",
		Pattern:     regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
		Countries:   []string{"EU"},
		Sensitivity: 1,
	},

	// Phone numbers (E.164 format + common EU formats)
	{
		Name:        "Phone Number",
		Type:        "phone",
		Pattern:     regexp.MustCompile(`\+?[1-9]\d{1,14}`),
		Countries:   []string{"EU"},
		Sensitivity: 1,
	},

	// IBAN (International Bank Account Number)
	{
		Name:        "IBAN",
		Type:        "iban",
		Pattern:     regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b`),
		Countries:   []string{"EU"},
		Sensitivity: 3,
	},

	// Credit card numbers (Luhn algorithm compatible)
	{
		Name:        "Credit Card",
		Type:        "credit_card",
		Pattern:     regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))\d{12}\b`),
		Countries:   []string{"Global"},
		Sensitivity: 3,
	},

	// VAT Numbers (EU format: country code + digits)
	{
		Name:        "VAT Number",
		Type:        "vat_id",
		Pattern:     regexp.MustCompile(`\b(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)U?[0-9A-Z]{8,12}\b`),
		Countries:   []string{"EU"},
		Sensitivity: 2,
	},

	// German SSN (Sozialversicherungsnummer)
	{
		Name:        "German SSN",
		Type:        "ssn",
		Pattern:     regexp.MustCompile(`\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\b`),
		Countries:   []string{"DE"},
		Sensitivity: 3,
	},

	// UK National Insurance Number
	{
		Name:        "UK National Insurance",
		Type:        "ssn",
		Pattern:     regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\b`),
		Countries:   []string{"GB"},
		Sensitivity: 3,
	},

	// French INSEE (Social Security Number)
	{
		Name:        "French INSEE",
		Type:        "ssn",
		Pattern:     regexp.MustCompile(`\b[12]\d{2}(0[1-9]|1[0-2])\d{8}\b`),
		Countries:   []string{"FR"},
		Sensitivity: 3,
	},

	// IP Address (IPv4 and IPv6)
	{
		Name:        "IP Address",
		Type:        "ip_address",
		Pattern:     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
		Countries:   []string{"Global"},
		Sensitivity: 1,
	},

	// Passport numbers (generic format)
	{
		Name:        "Passport Number",
		Type:        "passport",
		Pattern:     regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`),
		Countries:   []string{"EU"},
		Sensitivity: 3,
	},
}
