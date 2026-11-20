package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"fmt"
)

// IntegrityReport is the result of an offline vault integrity check.
type IntegrityReport struct {
	// Entries is the number of stored secrets.
	Entries int
	// Undecryptable names the entries that do not authenticate under the
	// given key (wrong key, or a corrupted or tampered entry).
	Undecryptable []string
}

// VerifyFile checks that EVERY entry of the vault file at path decrypts and
// authenticates under key, whatever its ACL. It is an offline integrity
// check for backups (#465), not an access path:
//
//   - the file is opened read-only (mode=ro): no schema statement, no
//     access-log row, no change to the file;
//   - ACLs are neither consulted nor changed: an ACL decides who may READ a
//     value at runtime, and this function returns no value;
//   - each plaintext is wiped as soon as the authentication tag has been
//     checked; only names and counts leave the function;
//   - it is reachable only from local code that already holds the vault key
//     and the file. No server route calls it.
func VerifyFile(ctx context.Context, path, key string) (*IntegrityReport, error) {
	keyBytes, err := resolveEncryptionKey(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT name, encrypted_value, nonce FROM secrets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("reading vault entries: %w", err)
	}
	defer rows.Close()
	rep := &IntegrityReport{}
	for rows.Next() {
		var name, value, nonce string
		if err := rows.Scan(&name, &value, &nonce); err != nil {
			return nil, fmt.Errorf("reading vault entries: %w", err)
		}
		rep.Entries++
		if !authenticates(gcm, value, nonce) {
			rep.Undecryptable = append(rep.Undecryptable, name)
		}
	}
	return rep, rows.Err()
}

// authenticates reports whether one stored entry opens under gcm. The
// plaintext never leaves this function.
func authenticates(gcm cipher.AEAD, valueB64, nonceB64 string) bool {
	ciphertext, err := base64.StdEncoding.DecodeString(valueB64)
	if err != nil {
		return false
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return false
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	for i := range plaintext {
		plaintext[i] = 0
	}
	return err == nil
}
