package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	dcrec "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/pkg/errors"

	"github.com/0xkey-io/sdk-go/internal/p256util"
)

const ECDSAPublicKeyBytes = 33

// ECDSAScheme identifies a supported ECDSA wire scheme.
type ECDSAScheme string

const (
	ECDSASchemeP256      ECDSAScheme = "SIGNATURE_SCHEME_TK_API_P256"
	ECDSASchemeSecp256k1 ECDSAScheme = "SIGNATURE_SCHEME_TK_API_SECP256K1"
)

// ECDSAKeyMaterial holds encoded key material and a signer.
type ECDSAKeyMaterial struct {
	PrivateKeyHex string
	PublicKeyHex  string
	Scheme        ECDSAScheme
	Signer        Signer
}

type ecdsaSigner struct {
	privKey *ecdsa.PrivateKey
	pubHex  string
	scheme  ECDSAScheme
}

func (s *ecdsaSigner) Sign(msg []byte) (string, error) {
	sigBytes, err := p256util.SignASN1(s.privKey, msg)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate signature")
	}

	return hex.EncodeToString(sigBytes), nil
}

func (s *ecdsaSigner) PublicKeyHex() string { return s.pubHex }

func (s *ecdsaSigner) Scheme() string { return string(s.scheme) }

// EncodeECDSAPrivateKey encodes a private scalar as hex.
func EncodeECDSAPrivateKey(privateKey *ecdsa.PrivateKey) string {
	return fmt.Sprintf("%064x", privateKey.D)
}

// EncodeECDSAPublicKey encodes a public key in compressed hex form.
func EncodeECDSAPublicKey(publicKey *ecdsa.PublicKey) string {
	prefix := "02"
	if publicKey.Y.Bit(0) != 0 {
		prefix = "03"
	}

	return fmt.Sprintf("%s%064x", prefix, publicKey.X)
}

// GenerateECDSAKey creates a new ECDSA keypair for the given scheme.
func GenerateECDSAKey(scheme ECDSAScheme) (*ECDSAKeyMaterial, error) {
	curve, err := curveForScheme(scheme)
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return MaterialFromECDSAPrivateKey(privateKey, scheme)
}

// MaterialFromECDSAPrivateKey builds key material from an existing private key.
func MaterialFromECDSAPrivateKey(privateKey *ecdsa.PrivateKey, scheme ECDSAScheme) (*ECDSAKeyMaterial, error) {
	if privateKey == nil || privateKey.X == nil {
		return nil, errors.New("empty key")
	}

	pubHex := EncodeECDSAPublicKey(&privateKey.PublicKey)

	return &ECDSAKeyMaterial{
		PrivateKeyHex: EncodeECDSAPrivateKey(privateKey),
		PublicKeyHex:  pubHex,
		Scheme:        scheme,
		Signer: &ecdsaSigner{
			privKey: privateKey,
			pubHex:  pubHex,
			scheme:  scheme,
		},
	}, nil
}

// ParseECDSAPrivateKeyHex loads key material from a hex-encoded private scalar.
func ParseECDSAPrivateKeyHex(encodedPrivateKey string, scheme ECDSAScheme) (*ECDSAKeyMaterial, error) {
	bytes, err := hex.DecodeString(encodedPrivateKey)
	if err != nil {
		return nil, err
	}

	curve, err := curveForScheme(scheme)
	if err != nil {
		return nil, err
	}

	dValue := new(big.Int).SetBytes(bytes)
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         dValue,
	}
	privateKey.X, privateKey.Y = curve.ScalarBaseMult(privateKey.D.Bytes())

	return MaterialFromECDSAPrivateKey(privateKey, scheme)
}

// DecodeECDSAPublicKeyHex parses a compressed public key for the given scheme.
func DecodeECDSAPublicKeyHex(encodedPublicKey string, scheme ECDSAScheme) (*ecdsa.PublicKey, error) {
	bytes, err := hex.DecodeString(encodedPublicKey)
	if err != nil {
		return nil, err
	}

	if len(bytes) != ECDSAPublicKeyBytes {
		return nil, fmt.Errorf("expected a 33-bytes-long public key (compressed). Got %d bytes", len(bytes))
	}

	switch scheme {
	case ECDSASchemeP256:
		curve := elliptic.P256()
		x, y := elliptic.UnmarshalCompressed(curve, bytes)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case ECDSASchemeSecp256k1:
		pubkey, err := dcrec.ParsePubKey(bytes)
		if err != nil {
			return nil, errors.New("cannot parse bytes into secp256k1 public key")
		}

		return &ecdsa.PublicKey{
			Curve: dcrec.S256(),
			X:     pubkey.X(),
			Y:     pubkey.Y(),
		}, nil
	default:
		return nil, fmt.Errorf("invalid signature scheme type: %s", scheme)
	}
}

func curveForScheme(scheme ECDSAScheme) (elliptic.Curve, error) {
	switch scheme {
	case ECDSASchemeP256:
		return elliptic.P256(), nil
	case ECDSASchemeSecp256k1:
		return dcrec.S256(), nil
	default:
		return nil, fmt.Errorf("invalid signature scheme type: %s", scheme)
	}
}
