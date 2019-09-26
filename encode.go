package oauth

import (
	"bytes"
	"fmt"
)

// PercentEncode percent encodes a string according to RFC 3986 2.1.
func PercentEncode(input string) string {
	var buf bytes.Buffer
	for _, b := range []byte(input) {
		if shouldEscape(b) {
			buf.Write([]byte(fmt.Sprintf("%%%02X", b)))
		} else {
			buf.WriteByte(b)
		}
	}
	return buf.String()
}

// The shouldEscape returns false if the byte is an unreserved character that
// should not be escaped and true otherwise, according to RFC 3986 2.1.
func shouldEscape(c byte) bool {
	// RFC3986 2.3 unreserved characters
	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}
	switch c {
	case '-', '.', '_', '~':
		return false
	}
	return true
}
