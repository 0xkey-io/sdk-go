package apikey

import (
	"crypto/ed25519"
	"fmt"

	"github.com/0xkey-io/sdk-go/internal/credential"
)

// FromED25519PrivateKey takes an ED25519 keypair and forms a 0xkey API key from it.
func FromED25519PrivateKey(privateKey ed25519.PrivateKey) (*Key, error) {
	material, err := credential.MaterialFromEd25519PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return keyFromEd25519Material(material), nil
}

func newED25519Key() (*Key, error) {
	material, err := credential.GenerateEd25519Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key pair: %s", err)
	}

	return keyFromEd25519Material(material), nil
}

func fromZeroXKeyED25519Key(encodedPrivateKey string) (*Key, error) {
	material, err := credential.ParseEd25519PrivateKeyHex(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	return keyFromEd25519Material(material), nil
}
