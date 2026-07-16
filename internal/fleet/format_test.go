package fleet

import "testing"

// formatMoney uses adaptive precision: two decimals normally, four when a
// non-zero amount would otherwise round to nothing (sub-cent LLM spend). The
// operator-facing regression this guards: a blocked agent's WHY rendering
// "daily budget exhausted ($0.00 / $0.00)".
func TestFormatMoneyAdaptivePrecision(t *testing.T) {
	cases := []struct {
		name     string
		currency string
		v        float64
		want     string
	}{
		{"zero stays 2dp", "USD", 0, "$0.00"},
		{"ordinary amount 2dp", "USD", 1.5, "$1.50"},
		{"dime boundary 2dp", "USD", 0.1, "$0.10"},
		{"sub-dime gets 4dp (field case: spend vs cap)", "USD", 0.0126, "$0.0126"},
		{"sub-cent gets 4dp", "USD", 0.0032, "$0.0032"},
		{"tiny sub-cent gets 4dp", "USD", 0.0001, "$0.0001"},
		{"euro sub-dime gets 4dp", "EUR", 0.0350, "€0.0350"},
		{"large amount unchanged", "EUR", 1000, "€1000.00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatMoney(tc.currency, tc.v); got != tc.want {
				t.Fatalf("FormatMoney(%q, %v) = %q, want %q", tc.currency, tc.v, got, tc.want)
			}
		})
	}
}
