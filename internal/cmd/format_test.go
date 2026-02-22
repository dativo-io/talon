package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatCost(t *testing.T) {
	assert.Equal(t, "0.000000", formatCost(0))
	assert.Equal(t, "< 0.0001", formatCost(0.00005))
	assert.Equal(t, "0.000100", formatCost(0.0001))
	assert.Equal(t, "1.234567", formatCost(1.234567))
}

func TestFormatCostNumeric(t *testing.T) {
	assert.Equal(t, "0.000000", formatCostNumeric(0))
	assert.Equal(t, "0.000050", formatCostNumeric(0.00005))
	assert.Equal(t, "1.234567", formatCostNumeric(1.234567))
}
