package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
)

const (
	Ed25519Scheme = "SIGNATURE_SCHEME_TK_API_ED25519"
)

// Ed25519KeyMaterial holds encoded Ed25519 key material and a signer.
type Ed25519KeyMaterial struct {
	PrivateKeyHex string
	PublicKeyHex  string
	Signer        Signer
}

type ed25519Signer struct {
	privKey ed25519.PrivateKey
	pubHex  string
}

func (s *ed25519Signer) Sign(msg []byte) (string, error) {
	return hex.EncodeToString(ed25519.Sign(s.privKey, msg)), nil
}

func (s *ed25519Signer) PublicKeyHex() string { return s.pubHex }

func (s *ed25519Signer) Scheme() string { return Ed25519Scheme }

// GenerateEd25519Key creates a new Ed25519 keypair.
func GenerateEd25519Key() (*Ed25519KeyMaterial, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return MaterialFromEd25519PrivateKey(privKey)
}

// MaterialFromEd25519PrivateKey builds key material from an existing private key.
func MaterialFromEd25519PrivateKey(privateKey ed25519.PrivateKey) (*Ed25519KeyMaterial, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("malformed ed25519 key pair (type assertion failed)")
	}

	pubHex := hex.EncodeToString(publicKey)

	return &Ed25519KeyMaterial{
		PrivateKeyHex: hex.EncodeToString(privateKey),
		PublicKeyHex:  pubHex,
		Signer: &ed25519Signer{
			privKey: privateKey,
			pubHex:  pubHex,
		},
	}, nil
}

// ParseEd25519PrivateKeyHex loads key material from hex.
func ParseEd25519PrivateKeyHex(encodedPrivateKey string) (*Ed25519KeyMaterial, error) {
	privateKeyBytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", ed25519.PrivateKeySize, len(privateKeyBytes))
	}

	return MaterialFromEd25519PrivateKey(ed25519.PrivateKey(privateKeyBytes))
}
