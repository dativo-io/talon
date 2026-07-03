package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

// The dashboard contract is that "alerts" is always an array. A nil slice
// from the store must serialize as [] — not null and not an absent key.
func TestGovernanceAlerts_EmptyStoreReturnsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(dir+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(nil, store, nil, nil, nil, "", nil, "admin-secret", map[string]string{})
	rec := doComplianceRequest(t, srv.Routes(), "/v1/dashboard/governance-alerts", adminHeader)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	raw, ok := resp["alerts"]
	require.True(t, ok, "response must carry an alerts key: %s", rec.Body.String())

	var alerts []json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &alerts), "alerts must be a JSON array, got: %s", string(raw))
	require.Empty(t, alerts)
}
