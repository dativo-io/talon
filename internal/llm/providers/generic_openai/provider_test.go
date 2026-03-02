package generic_openai

import (
	"net/http"
	"strings"
	"testing"

	openaisdk "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestGenericOpenAIWithHTTPClient(t *testing.T) {
	config := openaisdk.DefaultConfig("key")
	config.BaseURL = strings.TrimRight("https://example.com", "/")
	if !strings.HasSuffix(config.BaseURL, "/v1") {
		config.BaseURL += "/v1"
	}
	prov := &GenericOpenAIProvider{
		client:       openaisdk.NewClientWithConfig(config),
		apiKey:       "key",
		baseURL:      "https://example.com",
		jurisdiction: "US",
	}
	p2 := prov.WithHTTPClient(&http.Client{})
	assert.NotNil(t, p2)
	assert.Equal(t, "generic-openai", p2.Name())
	copy, ok := p2.(*GenericOpenAIProvider)
	require.True(t, ok)
	assert.NotSame(t, prov, copy)
}
