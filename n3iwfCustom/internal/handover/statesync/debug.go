package statesync

import (
	"crypto/sha256"
	"fmt"
)

func keyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	sum := sha256.Sum256(key)
	// Short fingerprint (12 hex chars) is enough for correlation across logs without exposing secrets.
	return fmt.Sprintf("%x", sum[:6])
}

