package classifier

import (
	"context"
	"testing"
)

func FuzzPIIRedactVerify(f *testing.F) {
	f.Add("Contact user@example.com and IBAN DE89370400440532013000")
	f.Add("Muller lives in Berlin")
	f.Add("Cafe\u0301 and emoji 👋🏽")
	f.Add("")

	scanner := MustNewScanner()
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, input string) {
		redacted := scanner.Redact(ctx, input)
		_ = scanner.VerifyEgress(ctx, redacted)
	})
}
