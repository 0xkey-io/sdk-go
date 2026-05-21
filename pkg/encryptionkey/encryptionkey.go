// Package encryptionkey manages encryption keys for users
package encryptionkey

import (
	"encoding/hex"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/0xkey-io/sdk-go/internal/credential"
)

// KemID for HPKE protocol.
const KemID hpke.KEM = hpke.KEM_P256_HKDF_SHA256

// SignerProductionPublicKey is the enclave quorum public key.
const SignerProductionPublicKey = "04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"

// Metadata stores non-secret metadata about the Encryption key.
type Metadata struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	User         string `json:"user"`
	PublicKey    string `json:"public_key"`
}

// Key defines a structure in which to hold both serialized and ecdh-lib-friendly versions of a 0xkey Encryption keypair.
type Key struct {
	Metadata

	EncodedPrivateKey string `json:"-"` // do not store the private key in the metadata file
	EncodedPublicKey  string `json:"public_key"`

	// Underlying KEM keypair
	privateKey *kem.PrivateKey
	publicKey  *kem.PublicKey
}

// New generates a new 0xkey encryption key.
func New(userID string, organizationID string) (*Key, error) {
	if userID == "" {
		return nil, errors.New("please supply a valid User UUID")
	}

	if _, err := uuid.Parse(userID); err != nil {
		return nil, errors.New("failed to parse user ID")
	}

	if organizationID == "" {
		return nil, errors.New("please supply a valid Organization UUID")
	}

	if _, err := uuid.Parse(organizationID); err != nil {
		return nil, errors.New("failed to parse organization ID")
	}

	_, privateKey, err := KemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	encryptionKey, err := FromKemPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	encryptionKey.Organization = organizationID
	encryptionKey.User = userID
	encryptionKey.PublicKey = encryptionKey.EncodedPublicKey

	return encryptionKey, nil
}

// EncodePrivateKey encodes a KEM private key into the 0xkey format.
// For now, "0xkey format" = raw DER form.
func EncodePrivateKey(privateKey kem.PrivateKey) (string, error) {
	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(privateKeyBytes), nil
}

// EncodePublicKey encodes a KEM public key into the 0xkey format.
// For now, "0xkey format" = raw DER form.
func EncodePublicKey(publicKey kem.PublicKey) (string, error) {
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(publicKeyBytes), nil
}

// FromKemPrivateKey takes a HPKE KEM keypair and forms a 0xkey encryption key from it.
// Assumes that privateKey.Public() has already been derived.
func FromKemPrivateKey(privateKey kem.PrivateKey) (*Key, error) {
	if privateKey == nil || privateKey.Public() == nil {
		return nil, errors.New("empty key")
	}

	publicKey := privateKey.Public()

	encodedPrivateKey, err := EncodePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	encodedPublicKey, err := EncodePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &Key{
		EncodedPrivateKey: encodedPrivateKey,
		EncodedPublicKey:  encodedPublicKey,
		publicKey:         &publicKey,
		privateKey:        &privateKey,
	}, nil
}

// FromZeroXKeyPrivateKey takes a 0xkey-encoded private key, derives a public key from it, and then returns the corresponding 0xkey API key.
func FromZeroXKeyPrivateKey(encodedPrivateKey string) (*Key, error) {
	bytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := KemID.Scheme().UnmarshalBinaryPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	encryptionKey, err := FromKemPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return encryptionKey, nil
}

// DecodeZeroXKeyPrivateKey takes a 0xkey-encoded private key and creates a KEM private key.
func DecodeZeroXKeyPrivateKey(encodedPrivateKey string) (*kem.PrivateKey, error) {
	bytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := KemID.Scheme().UnmarshalBinaryPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	return &privateKey, nil
}

// DecodeZeroXKeyPublicKey takes a 0xkey-encoded public key and creates a KEM public key.
func DecodeZeroXKeyPublicKey(encodedPublicKey string) (*kem.PublicKey, error) {
	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := KemID.Scheme().UnmarshalBinaryPublicKey(bytes)
	if err != nil {
		return nil, err
	}

	return &publicKey, nil
}

// GetCurve returns the curve used.
func (k Key) GetCurve() string {
	return ""
}

// GetPublicKey gets the key's public key.
func (k Key) GetPublicKey() string {
	return k.EncodedPublicKey
}

// GetPrivateKey gets the key's private key.
func (k Key) GetPrivateKey() string {
	return k.EncodedPrivateKey
}

// GetMetadata gets the key's metadata.
func (k Key) GetMetadata() Metadata {
	return k.Metadata
}

// LoadMetadata loads a JSON metadata file.
func (k Key) LoadMetadata(fn string) (*Metadata, error) {
	return credential.LoadJSONMetadata(fn, new(Metadata))
}

// MergeMetadata merges the given metadata with the api key.
func (k *Key) MergeMetadata(md Metadata) error {
	if k.EncodedPublicKey != md.PublicKey {
		return errors.Errorf("metadata public key %q does not match encryption key public key %q", md.PublicKey, k.EncodedPublicKey)
	}

	k.Name = md.Name
	k.Organization = md.Organization
	k.PublicKey = md.PublicKey
	k.User = md.User

	return nil
}
