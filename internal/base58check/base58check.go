// Package base58check implements checksum validation used by auth bundles.
package base58check

import (
	"crypto/sha256"
	"fmt"
	"reflect"
)

// Checksum returns the first four bytes of double-SHA256(payload).
func Checksum(payload []byte) [4]byte {
	h := sha256.Sum256(payload)
	h2 := sha256.Sum256(h[:])

	var checkSum [4]byte
	copy(checkSum[:], h2[:4])

	return checkSum
}

// Validate ensures payload ends with a valid checksum.
func Validate(payload []byte) error {
	if len(payload) < 5 {
		return fmt.Errorf("payload length is < 5 (length: %d)", len(payload))
	}

	expected := Checksum(payload[:len(payload)-4])
	if !reflect.DeepEqual(expected[:], payload[len(payload)-4:]) {
		return fmt.Errorf("checksum mismatch for payload %02x: %v (computed) != %v (last four bytes)", payload, expected, payload[len(payload)-4:])
	}

	return nil
}
