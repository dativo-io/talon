package classifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateBSN(t *testing.T) {
	tests := []struct {
		name      string
		digits    string
		wantValid bool
	}{
		{"valid BSN 1", "123456782", true}, // 9*1+8*2+7*3+6*4+5*5+4*6+3*7+2*8-1*2 = 9+16+21+24+25+24+21+16-2 = 154, 154%11 = 0
		{"valid BSN 2", "000000000", true}, // all zeros: sum 0, 0%11 = 0
		{"wrong length 8", "12345678", false},
		{"wrong length 10", "1234567890", false},
		{"invalid checksum", "123456789", false},
		{"non-digits", "12345678a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateBSN(tt.digits)
			assert.Equal(t, tt.wantValid, got)
		})
	}
}

func TestValidatePESEL(t *testing.T) {
	// Valid PESEL: weights 1,3,7,9,1,3,7,9,1,3; control = (10 - (sum mod 10)) mod 10.
	tests := []struct {
		name      string
		digits    string
		wantValid bool
	}{
		{"valid PESEL", "12345678903", true}, // sum 217, check digit 3
		{"valid PESEL 2", "02070803628", true},
		{"wrong length 10", "4405140135", false},
		{"wrong length 12", "440514013581", false},
		{"invalid check digit", "12345678902", false}, // last digit should be 3
		{"non-digits", "4405140135x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validatePESEL(tt.digits)
			assert.Equal(t, tt.wantValid, got)
		})
	}
}

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		number    string
		wantValid bool
	}{
		{"4111111111111111", true},
		{"5500000000000004", true},
		{"4111111111111112", false},
		{"1", false},
		{"12", false},
	}
	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			assert.Equal(t, tt.wantValid, luhnValid(tt.number))
		})
	}
}
