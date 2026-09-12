// Package attestedstamper creates Turnkey-compatible X-Stamp-Attested headers.
package attestedstamper

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

const HeaderName = "X-Stamp-Attested"

type Scheme string

const (
	SchemeP256OIDC              Scheme = "STAMP_ATTESTED_SCHEME_P256_OIDC"
	SchemeP256VerificationToken Scheme = "STAMP_ATTESTED_SCHEME_P256_VERIFICATION_TOKEN"
)

type Config struct {
	AttestedIdentity string
	PublicKey        string
	Scheme           Scheme
}

type Signer interface {
	Sign(payload []byte, publicKey string) (derSignatureHex string, err error)
}

type Stamp struct {
	HeaderName  string
	HeaderValue string
}

type Stamper struct {
	mu       sync.RWMutex
	signer   Signer
	identity string
	key      string
	scheme   Scheme
}

func New(signer Signer) *Stamper { return &Stamper{signer: signer} }

// String deliberately excludes identity and signer material.
func (s *Stamper) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("AttestedStamper{configured:%t,scheme:%s}", s.identity != "" && s.key != "", s.scheme)
}

func (s *Stamper) Configure(config Config) error {
	if config.AttestedIdentity == "" || config.PublicKey == "" {
		return errors.New("attested identity and public key are required")
	}
	if config.Scheme != SchemeP256OIDC && config.Scheme != SchemeP256VerificationToken {
		return fmt.Errorf("unsupported attested scheme: %s", config.Scheme)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity, s.key, s.scheme = config.AttestedIdentity, config.PublicKey, config.Scheme
	return nil
}

func (s *Stamper) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity, s.key, s.scheme = "", "", ""
}

func (s *Stamper) Stamp(payload []byte) (Stamp, error) {
	s.mu.RLock()
	signer, identity, key, scheme := s.signer, s.identity, s.key, s.scheme
	s.mu.RUnlock()
	if signer == nil || identity == "" || key == "" {
		return Stamp{}, errors.New("attested stamper is not configured")
	}
	signature, err := signer.Sign(payload, key)
	if err != nil {
		return Stamp{}, fmt.Errorf("sign attested payload: %w", err)
	}
	signature, err = normalizeLowS(signature)
	if err != nil {
		return Stamp{}, err
	}
	wire, err := json.Marshal(struct {
		PublicKeyAttestation string `json:"publicKeyAttestation"`
		Scheme               Scheme `json:"scheme"`
		PublicKey            string `json:"publicKey"`
		Signature            string `json:"signature"`
	}{identity, scheme, key, signature})
	if err != nil {
		return Stamp{}, fmt.Errorf("encode attested stamp: %w", err)
	}
	return Stamp{HeaderName: HeaderName, HeaderValue: base64.RawURLEncoding.EncodeToString(wire)}, nil
}

//nolint:gocyclo // DER parsing keeps each malformed/range case explicit and fail closed.
func normalizeLowS(signatureHex string) (string, error) {
	raw, err := hex.DecodeString(signatureHex)
	if err != nil {
		return "", fmt.Errorf("decode DER signature: %w", err)
	}
	var signature struct{ R, S *big.Int }
	if rest, unmarshalErr := asn1.Unmarshal(raw, &signature); unmarshalErr != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return "", errors.New("invalid DER signature")
	}
	order := elliptic.P256().Params().N
	if signature.R.Sign() <= 0 || signature.R.Cmp(order) >= 0 || signature.S.Sign() <= 0 || signature.S.Cmp(order) >= 0 {
		return "", errors.New("invalid P-256 signature values")
	}
	if signature.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		signature.S.Sub(order, signature.S)
	}
	normalized, err := asn1.Marshal(signature)
	if err != nil {
		return "", fmt.Errorf("encode DER signature: %w", err)
	}
	return hex.EncodeToString(normalized), nil
}
