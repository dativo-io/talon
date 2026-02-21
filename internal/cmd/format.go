package cmd

import (
	"fmt"
	"strconv"
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
