package cmd

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatCost(t *testing.T) {
	tests := []struct {
		name string
		c    float64
		want string
	}{
		{"zero", 0, "< 0.0001"},
		{"tiny positive below threshold", 0.00005, "< 0.0001"},
		{"just below threshold", 0.0000999, "< 0.0001"},
		{"boundary exactly 0.0001", 0.0001, "0.000100"},
		{"small positive", 0.0003, "0.000300"},
		{"sub-cent", 0.0015, "0.001500"},
		{"normal", 1.5, "1.500000"},
		{"large", 1000.25, "1000.250000"},
		{"negative", -0.5, "-0.500000"},
		{"negative tiny", -0.00001, "-0.000010"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCost(tt.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatCostNumeric(t *testing.T) {
	tests := []struct {
		name string
		c    float64
	}{
		{"zero", 0},
		{"tiny positive", 0.00005},
		{"small positive", 0.0003},
		{"normal", 1.5},
		{"negative", -0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCostNumeric(tt.c)
			_, err := strconv.ParseFloat(got, 64)
			assert.NoError(t, err, "formatCostNumeric must produce parseable numeric string, got %q", got)
		})
	}
}
