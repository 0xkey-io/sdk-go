package apikey

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/0xkey-io/sdk-go/internal/credential"
)

// ZeroXKeyECDSAPublicKeyBytes is the expected number of bytes for a public ECDSA key.
const ZeroXKeyECDSAPublicKeyBytes = credential.ECDSAPublicKeyBytes

// EncodePrivateECDSAKey encodes an ECDSA private key into the 0xkey format.
func EncodePrivateECDSAKey(privateKey *ecdsa.PrivateKey) string {
	return credential.EncodeECDSAPrivateKey(privateKey)
}

// EncodePublicECDSAKey encodes an ECDSA public key into the 0xkey format.
func EncodePublicECDSAKey(publicKey *ecdsa.PublicKey) string {
	return credential.EncodeECDSAPublicKey(publicKey)
}

// FromECDSAPrivateKey takes an ECDSA keypair and forms a 0xkey API key from it.
func FromECDSAPrivateKey(privateKey *ecdsa.PrivateKey, scheme signatureScheme) (*Key, error) {
	material, err := credential.MaterialFromECDSAPrivateKey(privateKey, toECDSAScheme(scheme))
	if err != nil {
		return nil, err
	}

	return keyFromECDSAMaterial(material, scheme), nil
}

// DecodeZeroXKeyPublicECDSAKey takes a 0xkey-encoded public key and creates an ECDSA public key.
func DecodeZeroXKeyPublicECDSAKey(encodedPublicKey string, scheme signatureScheme) (*ecdsa.PublicKey, error) {
	return credential.DecodeECDSAPublicKeyHex(encodedPublicKey, toECDSAScheme(scheme))
}

func newECDSAKey(scheme signatureScheme) (*Key, error) {
	material, err := credential.GenerateECDSAKey(toECDSAScheme(scheme))
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key pair: %s", scheme, err)
	}

	return keyFromECDSAMaterial(material, scheme), nil
}

func fromZeroXKeyECDSAKey(encodedPrivateKey string, scheme signatureScheme) (*Key, error) {
	material, err := credential.ParseECDSAPrivateKeyHex(encodedPrivateKey, toECDSAScheme(scheme))
	if err != nil {
		return nil, err
	}

	return keyFromECDSAMaterial(material, scheme), nil
}
