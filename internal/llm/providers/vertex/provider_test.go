package vertex

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVertexWithHTTPClient(t *testing.T) {
	prov := &VertexProvider{project: "proj", region: "europe-west1"}
	p2 := prov.WithHTTPClient(&http.Client{})
	require.NotNil(t, p2)
	assert.Equal(t, "vertex", p2.Name())
	copy, ok := p2.(*VertexProvider)
	require.True(t, ok)
	assert.NotSame(t, prov, copy, "WithHTTPClient must return a copy of the provider")
}

func TestVertexMetadata(t *testing.T) {
	p := &VertexProvider{}
	meta := p.Metadata()
	assert.Equal(t, "vertex", meta.ID)
	assert.Len(t, meta.EURegions, 3)
	assert.Equal(t, 70, meta.Wizard.Order)
}
