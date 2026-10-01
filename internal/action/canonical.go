package action

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Canonical JSON (#427 binding contract).
//
// The digest binds the COMPLETE normalized argument payload, so the
// canonical form must be deterministic and lossless:
//   - object keys sorted bytewise, duplicates rejected;
//   - numbers kept as their source literal (json.Number), so 1 and 1.0
//     are different arguments and no float64 round-trip can alter them;
//   - strings re-encoded without HTML escaping, must be valid UTF-8;
//   - arrays keep order; explicit null is preserved (absent ≠ null);
//   - no insignificant whitespace.

// MaxArgumentBytes bounds an argument payload before any parsing work.
const MaxArgumentBytes = 256 * 1024

// maxDepth bounds nesting so a hostile payload cannot exhaust the stack.
const maxDepth = 32

// Canonicalize returns the canonical encoding of a JSON document.
func Canonicalize(raw []byte) ([]byte, error) {
	if len(raw) > MaxArgumentBytes {
		return nil, fmt.Errorf("arguments exceed %d bytes", MaxArgumentBytes)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("arguments are not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var buf bytes.Buffer
	if err := canonicalValue(dec, &buf, 0); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return buf.Bytes(), nil
}

// Digest returns the sha256 hex of bytes.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func canonicalValue(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("nesting exceeds %d levels", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return canonicalObject(dec, out, depth)
		case '[':
			out.WriteByte('[')
			first := true
			for dec.More() {
				if !first {
					out.WriteByte(',')
				}
				first = false
				if err := canonicalValue(dec, out, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // ']'
				return fmt.Errorf("invalid JSON: %w", err)
			}
			out.WriteByte(']')
			return nil
		}
		return fmt.Errorf("unexpected delimiter %v", v)
	case string:
		return writeString(out, v)
	case json.Number:
		out.WriteString(v.String())
		return nil
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
		return nil
	case nil:
		out.WriteString("null")
		return nil
	}
	return fmt.Errorf("unsupported JSON token %T", tok)
}

func canonicalObject(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	type member struct {
		key string
		val []byte
	}
	var members []member
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("object key is not a string")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate object key %q", key)
		}
		seen[key] = struct{}{}
		var vb bytes.Buffer
		if err := canonicalValue(dec, &vb, depth+1); err != nil {
			return err
		}
		members = append(members, member{key: key, val: vb.Bytes()})
	}
	if _, err := dec.Token(); err != nil { // '}'
		return fmt.Errorf("invalid JSON: %w", err)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].key < members[j].key })
	out.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := writeString(out, m.key); err != nil {
			return err
		}
		out.WriteByte(':')
		out.Write(m.val)
	}
	out.WriteByte('}')
	return nil
}

func writeString(out *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("string is not valid UTF-8")
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	out.WriteString(strings.TrimSuffix(b.String(), "\n"))
	return nil
}
