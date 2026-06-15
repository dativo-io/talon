package classifier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recognizerMatrixCase struct {
	positive string
	negative string
}

func containsEntityType(entities []PIIEntity, want string) bool {
	for _, e := range entities {
		if e.Type == want {
			return true
		}
	}
	return false
}

func TestRecognizerMatrix_AllBuiltInsHavePositiveAndNegativeCoverage(t *testing.T) {
	matrix := map[string]recognizerMatrixCase{
		"Email Address":                      {positive: "Email user@example.com", negative: "No personal data present"},
		"Phone Number":                       {positive: "Call +49 30 1234567", negative: "No personal data present"},
		"IBAN":                               {positive: "IBAN DE89370400440532013000", negative: "No personal data present"},
		"Credit Card":                        {positive: "Card 4111111111111111", negative: "No personal data present"},
		"VAT Number":                         {positive: "VAT ID DE123456789", negative: "No personal data present"},
		"German SSN":                         {positive: "Sozialversicherungsnummer 12 123456 A 123", negative: "No personal data present"},
		"UK National Insurance":              {positive: "NI number AB123456C", negative: "No personal data present"},
		"French INSEE":                       {positive: "INSEE 1850775012345", negative: "No personal data present"},
		"IP Address":                         {positive: "Server IP 192.168.1.100", negative: "No personal data present"},
		"Passport Number":                    {positive: "Passport number AB1234567", negative: "No personal data present"},
		"German Personalausweisnummer":       {positive: "Personalausweis L01X00TT42", negative: "No personal data present"},
		"German Steuer-ID":                   {positive: "Steuer-ID 12345678901", negative: "No personal data present"},
		"French NIR":                         {positive: "NIR 185077501234567", negative: "No personal data present"},
		"French Carte d'identite":            {positive: "Carte d'identité 123456789012", negative: "No personal data present"},
		"Dutch BSN":                          {positive: "BSN 123456782", negative: "No personal data present"},
		"Polish PESEL":                       {positive: "PESEL 12345678903", negative: "No personal data present"},
		"Polish NIP":                         {positive: "NIP 123-456-32-18", negative: "No personal data present"},
		"Spanish DNI":                        {positive: "DNI 12345678Z", negative: "No personal data present"},
		"Spanish NIE":                        {positive: "NIE X1234567L", negative: "No personal data present"},
		"Belgian Rijksregisternummer":        {positive: "Rijksregisternummer 12.34.56-789.12", negative: "No personal data present"},
		"Austrian Sozialversicherungsnummer": {positive: "Sozialversicherungsnummer 1234010190", negative: "No personal data present"},
		"IMSI":                               {positive: "IMSI 232011234567890", negative: "No personal data present"},
		"ICCID":                              {positive: "ICCID 8943102012345678901", negative: "No personal data present"},
		"EID (eUICC identifier)":             {positive: "eUICC EID 12345678901234567890123456789012", negative: "No personal data present"},
		"Swedish Personnummer":               {positive: "Personnummer 550713-1234", negative: "No personal data present"},
		"Danish CPR-nummer":                  {positive: "CPR 010190-1234", negative: "No personal data present"},
		"Irish PPS Number":                   {positive: "PPS number 1234567T", negative: "No personal data present"},
		"Portuguese NIF":                     {positive: "NIF 123456789", negative: "No personal data present"},
		"Person (title + name)":              {positive: "Customer Mrs Smith lives in Berlin", negative: "No personal data present"},
		"Location (known places)":            {positive: "Office city Berlin", negative: "No personal data present"},
	}

	defaults, err := DefaultRecognizers()
	require.NoError(t, err)

	scanner := MustNewScanner()
	ctx := context.Background()

	for _, rec := range defaults {
		tc, ok := matrix[rec.Name]
		if !ok {
			t.Fatalf("matrix missing recognizer %q", rec.Name)
		}
		wantType := entityToType(rec.SupportedEntity)

		pos := scanner.Scan(ctx, tc.positive)
		require.Truef(t, containsEntityType(pos.Entities, wantType),
			"positive case for %q must detect type %q; got entities=%+v",
			rec.Name, wantType, pos.Entities)

		neg := scanner.Scan(ctx, tc.negative)
		assert.Falsef(t, containsEntityType(neg.Entities, wantType),
			"negative case for %q must not detect type %q; got entities=%+v",
			rec.Name, wantType, neg.Entities)
	}
}
