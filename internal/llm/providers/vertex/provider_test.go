package vertex

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVertexMetadata(t *testing.T) {
	p := &VertexProvider{}
	meta := p.Metadata()
	assert.Equal(t, "vertex", meta.ID)
	assert.Len(t, meta.EURegions, 3)
	assert.Equal(t, 70, meta.Wizard.Order)
}
