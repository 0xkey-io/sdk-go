package p256util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// ParseUncompressedPublicKeyHex decodes a hex-encoded 65-byte uncompressed P-256 point.
func ParseUncompressedPublicKeyHex(encoded string) (*ecdsa.PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid notarizer public key encoding: %w", err)
	}

	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed public key format: expected 65 bytes starting with 0x04, got %d bytes", len(pubKeyBytes))
	}

	return ParseUncompressedPoint65(pubKeyBytes)
}

// ParseCompressedPublicKeyHex decodes a hex-encoded compressed P-256 public key.
func ParseCompressedPublicKeyHex(encoded string) (*ecdsa.PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid public key encoding: %w", err)
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubKeyBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid public key format")
	}

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// VerifySHA256RawP1363 verifies an IEEE P1363 ECDSA signature over SHA-256(message).
func VerifySHA256RawP1363(publicKey *ecdsa.PublicKey, message, sigBytes []byte) error {
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	digest := sha256.Sum256(message)
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return fmt.Errorf("session JWT signature verification failed")
	}

	return nil
}
