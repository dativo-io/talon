package cryptoutil

// IsHexString reports whether s consists entirely of hexadecimal characters
// (0-9, a-f, A-F). It returns true for an empty string — callers should check
// length separately when a minimum size is required.
func IsHexString(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
