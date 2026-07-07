package cmd

import (
	"fmt"
	"strconv"

	"github.com/dativo-io/talon/internal/pricing"
)

// formatCost formats cost for display: zero as "0.000000", sub-cent as 6 decimals or "< 0.0001" for tiny positive amounts.
func formatCost(c float64) string {
	if c == 0 {
		return "0.000000"
	}
	if c > 0 && c < 0.0001 {
		return "< 0.0001"
	}
	return fmt.Sprintf("%.6f", c)
}

// formatCostNumeric formats cost as a numeric string for machine-readable export (e.g. CSV).
// Always returns a valid number parseable by spreadsheets and BI tools; never "< 0.0001".
func formatCostNumeric(c float64) string {
	return strconv.FormatFloat(c, 'f', 6, 64)
}

// formatMoney renders a cost with its currency unit (#216): the symbol for
// USD/EUR, the code as a prefix otherwise. An empty currency (records that
// predate the stamp, or no pricing table in scope) renders as USD — the unit
// the shipped pricing tables were always denominated in.
func formatMoney(currency string, c float64) string {
	return pricing.FormatAmount(currency, formatCost(c))
}

// exportCurrency is the machine-readable currency column value (#216):
// records that predate the currency stamp default to USD, the unit the
// shipped pricing tables were always denominated in.
func exportCurrency(currency string) string {
	if currency == "" {
		return pricing.DefaultCurrency
	}
	return currency
}
