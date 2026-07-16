package fleet

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/pricing"
)

// WhyString renders the WHY column for a row: an em dash when there is no cause,
// otherwise the first cause's detail (the causes are already in the fixed #270
// priority order) plus a "(+N more)" suffix when several matched.
func WhyString(causes []Cause) string {
	if len(causes) == 0 {
		return "—"
	}
	why := causes[0].Detail
	if n := len(causes) - 1; n > 0 {
		why = fmt.Sprintf("%s (+%d more)", why, n)
	}
	return why
}

// formatMoney renders an amount in the given ISO-4217 currency using the shared
// pricing formatter (USD → $, EUR → €), so the attention queue reads in the
// same currency and symbol as `talon costs`. An empty code defaults to USD, the
// honest default for the shipped pricing tables (#216).
//
// Precision is adaptive: two decimals for ordinary amounts, four when a non-zero
// amount would otherwise round to nothing (0 < |v| < 0.01). LLM spend is often
// sub-cent; without this, a blocked agent's WHY read "daily budget exhausted
// ($0.00 / $0.00)" — true, but useless to the operator deciding what to do.
func formatMoney(currency string, v float64) string {
	digits := 2
	if av := math.Abs(v); av > 0 && av < 0.01 {
		digits = 4
	}
	return pricing.FormatAmount(currency, strconv.FormatFloat(v, 'f', digits, 64))
}

// FormatMoney is the exported form used by the CLI/handler renderers so the COST
// column is formatted in exactly one place.
func FormatMoney(currency string, v float64) string { return formatMoney(currency, v) }

// humanWindow renders a rolling-window duration compactly ("1h", "24h", "30m")
// for cause details.
func humanWindow(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	s := strings.TrimSuffix(d.String(), "0s")
	if s == "" {
		return d.String()
	}
	return s
}
