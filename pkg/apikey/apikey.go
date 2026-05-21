// Package apikey manages 0xkey API keys for organizations
package apikey

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/0xkey-io/sdk-go/internal/credential"
)

// Metadata stores non-secret metadata about the API key.
type Metadata struct {
	Name          string   `json:"name"`
	Organizations []string `json:"organizations"`
	PublicKey     string   `json:"public_key"`
	Scheme        string   `json:"scheme"`
}

// Key defines a structure in which to hold both serialized and ecdsa-lib-friendly versions of a 0xkey API keypair.
type Key struct {
	Metadata

	EncodedPrivateKey string `json:"-"` // do not store the private key in the metadata file
	EncodedPublicKey  string `json:"public_key"`

	scheme signatureScheme
	signer credential.Signer
}

// APIStamp defines the stamp format used to authenticate payloads to the API.
type APIStamp struct {
	// API public key, hex-encoded
	PublicKey string `json:"publicKey"`

	// Signature is the P-256 signature bytes, hex-encoded
	Signature string `json:"signature"`

	// Signature scheme. Can be set to "SIGNATURE_SCHEME_TK_API_P256", "SIGNATURE_SCHEME_TK_API_SECP256K1",
	// or "SIGNATURE_SCHEME_TK_API_ED25519"
	Scheme signatureScheme `json:"scheme"`
}

// New generates a new 0xkey API key.
func New(organizationID string, opts ...optionFunc) (*Key, error) {
	if organizationID == "" {
		return nil, errors.New("please supply a valid Organization UUID")
	}

	if _, err := uuid.Parse(organizationID); err != nil {
		return nil, errors.New("failed to parse organization ID")
	}

	key := &Key{scheme: defaultSignatureScheme}
	for _, opt := range opts {
		opt(key)
	}

	var (
		generated *Key
		err       error
	)

	switch key.scheme {
	case SchemeP256, SchemeSECP256K1:
		generated, err = newECDSAKey(key.scheme)
	case SchemeED25519:
		generated, err = newED25519Key()
	default:
		return nil, fmt.Errorf("unsupported signature scheme: %s", key.scheme)
	}

	if err != nil {
		return nil, err
	}

	generated.Organizations = append(generated.Organizations, organizationID)
	generated.PublicKey = generated.EncodedPublicKey
	generated.Scheme = string(generated.scheme)

	return generated, nil
}

// FromZeroXKeyPrivateKey takes a 0xkey-encoded private key, derives a public key from it, and then returns the corresponding 0xkey API key.
func FromZeroXKeyPrivateKey(encodedPrivateKey string, scheme signatureScheme) (*Key, error) {
	switch scheme {
	case SchemeP256, SchemeSECP256K1:
		return fromZeroXKeyECDSAKey(encodedPrivateKey, scheme)
	case SchemeED25519:
		return fromZeroXKeyED25519Key(encodedPrivateKey)
	default:
		return nil, errors.New("unsupported signature scheme")
	}
}

// Stamp generates a signing stamp for the given message with the given API key.
// The resulting stamp should be added as the "X-Stamp" header of an API request.
func Stamp(message []byte, apiKey *Key) (string, error) {
	return credential.EncodeStamp(message, apiKey.signer)
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

// GetCurve returns the curve used; defaults to p256 for backwards compatibility with keys
// created before there were multiple supported types.
func (k Key) GetCurve() string {
	switch k.scheme {
	case SchemeSECP256K1:
		return string(CurveSecp256k1)
	case SchemeED25519:
		return string(CurveEd25519)
	case SchemeP256:
		return string(CurveP256)
	default:
		return string(CurveP256)
	}
}

// LoadMetadata loads a JSON metadata file.
func (k Key) LoadMetadata(fn string) (*Metadata, error) {
	return credential.LoadJSONMetadata(fn, new(Metadata))
}

// MergeMetadata merges the given metadata with the api key.
func (k *Key) MergeMetadata(md Metadata) error {
	if k.EncodedPublicKey != md.PublicKey {
		return errors.Errorf("metadata public key %q does not match API key public key %q", md.PublicKey, k.EncodedPublicKey)
	}

	k.Name = md.Name
	k.Organizations = md.Organizations
	k.PublicKey = md.PublicKey
	k.Scheme = md.Scheme

	return nil
}

func keyFromECDSAMaterial(material *credential.ECDSAKeyMaterial, scheme signatureScheme) *Key {
	return &Key{
		EncodedPrivateKey: material.PrivateKeyHex,
		EncodedPublicKey:  material.PublicKeyHex,
		scheme:            scheme,
		signer:            material.Signer,
	}
}

func keyFromEd25519Material(material *credential.Ed25519KeyMaterial) *Key {
	return &Key{
		EncodedPrivateKey: material.PrivateKeyHex,
		EncodedPublicKey:  material.PublicKeyHex,
		scheme:            SchemeED25519,
		signer:            material.Signer,
	}
}

func toECDSAScheme(scheme signatureScheme) credential.ECDSAScheme {
	return credential.ECDSAScheme(scheme)
}
