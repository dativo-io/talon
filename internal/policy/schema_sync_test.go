package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAgentSchemaFileInSync guards against the documented schema copy at
// schemas/agent.talon.schema.json drifting from the canonical embedded schema
// used by `talon validate` (internal/policy/agent.talon.schema.json).
func TestAgentSchemaFileInSync(t *testing.T) {
	copyPath := filepath.Join("..", "..", "schemas", "agent.talon.schema.json")
	copyBytes, err := os.ReadFile(copyPath)
	require.NoError(t, err, "schemas/agent.talon.schema.json must exist")

	var embedded, fileCopy interface{}
	require.NoError(t, json.Unmarshal([]byte(schemaV2), &embedded), "embedded schema must be valid JSON")
	require.NoError(t, json.Unmarshal(copyBytes, &fileCopy), "schema copy must be valid JSON")

	assert.Equal(t, embedded, fileCopy,
		"schemas/agent.talon.schema.json is out of sync with internal/policy/agent.talon.schema.json — run: cp internal/policy/agent.talon.schema.json schemas/agent.talon.schema.json")
}
