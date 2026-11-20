package secrets

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MetadataReadOnly reads one secret's metadata (never its value) from the
// vault file at path through a read-only connection: no schema statement, no
// access-log row, no change to the file, and no encryption key is needed.
// It is for inspection that must not initialize or touch a vault (a dry
// run). ErrSecretNotFound when the name is absent or the file holds no
// vault yet.
func MetadataReadOnly(ctx context.Context, path, name string) (*SecretMetadata, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var m SecretMetadata
	var aclJSON string
	err = db.QueryRowContext(ctx, `SELECT name, acl_json, created_at FROM secrets WHERE name = ?`, name).Scan(&m.Name, &aclJSON, &m.CreatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrSecretNotFound
	case err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table"):
		return nil, ErrSecretNotFound
	case err != nil:
		return nil, fmt.Errorf("reading secret metadata: %w", err)
	}
	if err := json.Unmarshal([]byte(aclJSON), &m.ACL); err != nil {
		return nil, fmt.Errorf("reading secret ACL: %w", err)
	}
	return &m, nil
}
