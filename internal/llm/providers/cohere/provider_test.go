package cohere

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCohereMetadata(t *testing.T) {
	p := &CohereProvider{}
	meta := p.Metadata()
	assert.Equal(t, "cohere", meta.ID)
	assert.Equal(t, "CA", meta.Jurisdiction)
	assert.Equal(t, 90, meta.Wizard.Order)
}
