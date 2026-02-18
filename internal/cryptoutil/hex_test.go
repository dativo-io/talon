package cryptoutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHexString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"lowercase hex", "deadbeef", true},
		{"uppercase hex", "DEADBEEF", true},
		{"mixed case", "DeAdBeEf", true},
		{"digits only", "0123456789", true},
		{"64 char key", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", true},
		{"contains g", "0123abcg", false},
		{"space", "ab cd", false},
		{"special char", "abcd!!", false},
		{"newline", "abcd\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsHexString(tt.in))
		})
	}
}
