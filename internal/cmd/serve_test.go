package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAPIKeys(t *testing.T) {
	m := parseAPIKeys("")
	assert.Empty(t, m)

	m = parseAPIKeys("key1")
	assert.Len(t, m, 1)
	assert.Equal(t, "default", m["key1"])

	m = parseAPIKeys("key1:acme,key2:tenant2")
	assert.Len(t, m, 2)
	assert.Equal(t, "acme", m["key1"])
	assert.Equal(t, "tenant2", m["key2"])

	// "mykey:" or "mykey:  " must map to default tenant (empty after colon = default)
	m = parseAPIKeys("mykey:")
	assert.Len(t, m, 1)
	assert.Equal(t, "default", m["mykey"], "key with trailing colon must get default tenant")

	m = parseAPIKeys("mykey:  ")
	assert.Len(t, m, 1)
	assert.Equal(t, "default", m["mykey"], "key with colon and spaces must get default tenant")
}
