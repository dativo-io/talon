package testutil

import (
	"path/filepath"
	"testing"

	"github.com/dativo-io/talon/internal/evidence"
)

// NewTestEvidenceStore creates an evidence store in a temp dir and registers
// t.Cleanup to close it. Uses TestSigningKey.
func NewTestEvidenceStore(t *testing.T) *evidence.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), TestSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}
