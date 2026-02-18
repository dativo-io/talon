package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/policy"
)

func TestEntityNames(t *testing.T) {
	tests := []struct {
		name     string
		entities []classifier.PIIEntity
		want     []string
	}{
		{
			name:     "empty",
			entities: nil,
			want:     nil,
		},
		{
			name: "deduplicates types",
			entities: []classifier.PIIEntity{
				{Type: "EMAIL_ADDRESS", Value: "a@b.com"},
				{Type: "EMAIL_ADDRESS", Value: "c@d.com"},
				{Type: "PHONE_NUMBER", Value: "+49123456"},
			},
			want: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"},
		},
		{
			name: "single entity",
			entities: []classifier.PIIEntity{
				{Type: "IBAN_CODE", Value: "DE89370400440532013000"},
			},
			want: []string{"IBAN_CODE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := entityNames(tt.entities)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestComplianceFromPolicy(t *testing.T) {
	t.Run("nil compliance", func(t *testing.T) {
		pol := &policy.Policy{}
		c := complianceFromPolicy(pol)
		assert.Nil(t, c.Frameworks)
		assert.Empty(t, c.DataLocation)
	})

	t.Run("with compliance", func(t *testing.T) {
		pol := &policy.Policy{
			Compliance: &policy.ComplianceConfig{
				Frameworks:    []string{"gdpr", "nis2"},
				DataResidency: "eu-west-1",
			},
		}
		c := complianceFromPolicy(pol)
		assert.Equal(t, []string{"gdpr", "nis2"}, c.Frameworks)
		assert.Equal(t, "eu-west-1", c.DataLocation)
	})
}
