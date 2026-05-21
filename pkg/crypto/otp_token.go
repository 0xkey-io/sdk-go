package crypto

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/0xkey-io/sdk-go/internal/p256util"
)

// VerifyOtpVerificationToken verifies the signature of an OTP verification token JWT
// using the production OTP verification public key.
func VerifyOtpVerificationToken(tokenString, dangerouslyOverridePublicKey string, parserOpts ...jwt.ParserOption) error {
	otpVerificationPublicKeyHex := ProductionOTPVerificationPublicKey
	if dangerouslyOverridePublicKey != "" {
		otpVerificationPublicKeyHex = dangerouslyOverridePublicKey
	}

	pubKey, err := p256util.ParseCompressedPublicKeyHex(otpVerificationPublicKeyHex)
	if err != nil {
		return err
	}

	parser := jwt.NewParser(parserOpts...)
	token, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected signing method: %v (expected ES256)", t.Method.Alg())
		}
		return pubKey, nil
	})
	if err != nil {
		return fmt.Errorf("failed to parse and verify token: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	return validateOtpVerificationTokenClaims(claims)
}

func validateOtpVerificationTokenClaims(claims jwt.MapClaims) error {
	for _, field := range []string{"id", "verification_type", "contact"} {
		if _, ok := claims[field].(string); !ok {
			return fmt.Errorf("token missing %q claim", field)
		}
	}
	return nil
}
