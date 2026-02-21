package cmd

import "fmt"

// formatCost formats cost for display: sub-cent as 6 decimals or "< 0.0001" for tiny amounts.
func formatCost(c float64) string {
	if c < 0.0001 && c >= 0 {
		return "< 0.0001"
	}
	if c < 0 {
		return fmt.Sprintf("%.6f", c)
	}
	return fmt.Sprintf("%.6f", c)
}
