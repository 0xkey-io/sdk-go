// Package p256util provides shared P-256 ECDSA helpers.
package p256util

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// SignASN1 signs msg with SHA-256 and returns an ASN.1 DER signature.
func SignASN1(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
}

// VerifyASN1 verifies an ASN.1 DER signature over SHA-256(msg).
func VerifyASN1(publicKey *ecdsa.PublicKey, msg, signature []byte) bool {
	hash := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

// ParseUncompressedPublicKey parses a 65-byte uncompressed P-256 point (0x04||X||Y).
func ParseUncompressedPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	byteLen := (elliptic.P256().Params().BitSize + 7) / 8
	if len(b) != 1+2*byteLen {
		return nil, errors.New("invalid enclave auth key length")
	}

	x := new(big.Int).SetBytes(b[1 : 1+byteLen])
	y := new(big.Int).SetBytes(b[1+byteLen:])

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// ParseUncompressedPoint65 parses a 65-byte uncompressed P-256 point for proof verification.
func ParseUncompressedPoint65(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 65 || b[0] != 0x04 {
		return nil, fmt.Errorf("want 65-byte uncompressed P-256 point (0x04||X||Y)")
	}

	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key bytes: %w", err)
	}

	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
