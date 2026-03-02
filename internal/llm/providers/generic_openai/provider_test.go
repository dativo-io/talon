package generic_openai

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenericOpenAIMetadata(t *testing.T) {
	p := &GenericOpenAIProvider{jurisdiction: "EU"}
	meta := p.Metadata()
	assert.Equal(t, "generic-openai", meta.ID)
	assert.Equal(t, "EU", meta.Jurisdiction)
	assert.Equal(t, 100, meta.Wizard.Order)
}

func TestGenericOpenAIMetadata_DefaultJurisdiction(t *testing.T) {
	p := &GenericOpenAIProvider{}
	meta := p.Metadata()
	assert.Equal(t, "US", meta.Jurisdiction)
}
