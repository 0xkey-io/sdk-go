package enclave_encrypt

import (
	"crypto/ecdsa"

	"github.com/0xkey-io/sdk-go/internal/base58check"
	"github.com/0xkey-io/sdk-go/internal/p256util"
)

// P256Sign signs msg with SHA-256 and returns an ASN.1 DER signature.
func P256Sign(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	return p256util.SignASN1(privateKey, msg)
}

// P256Verify verifies an ASN.1 DER signature over SHA-256(msg).
func P256Verify(publicKey *ecdsa.PublicKey, msg []byte, signature []byte) bool {
	return p256util.VerifyASN1(publicKey, msg, signature)
}

// ToEcdsaPublic parses a 65-byte uncompressed P-256 public key.
func ToEcdsaPublic(publicBytes []byte) (*ecdsa.PublicKey, error) {
	return p256util.ParseUncompressedPublicKey(publicBytes)
}

// Validates that a payload has a valid checksum in the last four bytes.
func ValidateChecksum(payload []byte) error {
	return base58check.Validate(payload)
}

func checksum(payload []byte) [4]byte {
	return base58check.Checksum(payload)
}
