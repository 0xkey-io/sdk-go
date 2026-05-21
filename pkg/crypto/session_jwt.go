package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/0xkey-io/sdk-go/internal/p256util"
)

// VerifySessionJwtSignature verifies the signature of a 0xkey session JWT using
// standard ES256 semantics with the production notarizer public key.
//
// Session JWTs use the standard ES256 signing scheme:
//   - SHA-256 hash over header.payload
//   - ECDSA signature with P-256 curve
//   - IEEE P1363 signature format (raw R || S concatenation, 64 bytes)
//   - Uncompressed public key (65 bytes, starts with 0x04)
func VerifySessionJwtSignature(jwtString string, dangerouslyOverrideNotarizerPublicKey ...string) error {
	notarizerPublicKeyHex := ProductionNotarizerPublicKey
	if len(dangerouslyOverrideNotarizerPublicKey) > 0 && dangerouslyOverrideNotarizerPublicKey[0] != "" {
		notarizerPublicKeyHex = dangerouslyOverrideNotarizerPublicKey[0]
	}

	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]

	pubKey, err := p256util.ParseUncompressedPublicKeyHex(notarizerPublicKeyHex)
	if err != nil {
		return err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	return p256util.VerifySHA256RawP1363(pubKey, []byte(signingInput), sigBytes)
}
