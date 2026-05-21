package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifySessionJwtSignature(t *testing.T) {
	validJWT, validPubKey := mustCreateSessionJWT(t)
	tests := []struct {
		name    string
		jwt     string
		pubKey  string
		wantErr bool
	}{
		{
			name:    "valid session JWT",
			jwt:     validJWT,
			pubKey:  validPubKey,
			wantErr: false,
		},
		{
			name:    "invalid format - too few parts",
			jwt:     "header.payload",
			wantErr: true,
		},
		{
			name:    "invalid format - too many parts",
			jwt:     "header.payload.signature.extra",
			wantErr: true,
		},
		{
			name:    "invalid base64 signature",
			jwt:     "header.payload.invalid!!!signature",
			wantErr: true,
		},
		{
			name:    "empty jwt",
			jwt:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.pubKey != "" {
				err = VerifySessionJwtSignature(tt.jwt, tt.pubKey)
			} else {
				err = VerifySessionJwtSignature(tt.jwt)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySessionJwtSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func mustCreateSessionJWT(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"sub":             "user-id",
		"organization_id": "org-id",
		"exp":             time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rb, sb := r.Bytes(), s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)

	//nolint:staticcheck
	pub := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), hex.EncodeToString(pub)
}

func TestVerifySessionJwtSignature_WithCustomKey(t *testing.T) {
	invalidKey := "invalid_hex"

	err := VerifySessionJwtSignature("header.payload.signature", invalidKey)
	if err == nil {
		t.Error("Expected error when using invalid hex key, got nil")
	}
}

func TestVerifyOtpVerificationToken(t *testing.T) {
	tests := []struct {
		name    string
		jwt     string
		wantErr bool
	}{
		{
			name: "valid OTP verification token (real 0xkey-signed, expiry bypassed)",
			jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJjb250YWN0IjoidXNlckBleGFtcGxlLmNvbSIsImV4cCI6MTc3MDc1MTgyMSwiaWQiOiI4ZmMxZDQ0NS05ZmI4LTQ3NWQtYWViNy04ZTlkOWY4ZjkwYTUiLCJ2ZXJpZmljYXRpb25fdHlwZSI6Ik9UUF9UWVBFX0VNQUlMIn0." +
				"YorjdeMCvQmjWe680OeWUDXB7LEBFudvGS8R8TP451DACO02MAyAlKOwXOulG9Z422qXMvVqn7mITT2f1hgWwQ",
			wantErr: false,
		},
		{
			name:    "invalid format - too few parts",
			jwt:     "header.payload",
			wantErr: true,
		},
		{
			name:    "empty jwt",
			jwt:     "",
			wantErr: true,
		},
	}

	// Freeze time to 1 second before the test token's expiry (exp: 1770751821).
	// This lets us verify the real 0xkey-signed token against ProductionOTPVerificationPublicKey
	// without needing a live token.
	frozenTime := jwt.WithTimeFunc(func() time.Time {
		return time.Unix(1770751820, 0)
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyOtpVerificationToken(tt.jwt, "", frozenTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyOtpVerificationToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyOtpVerificationToken_WithCustomKey(t *testing.T) {
	err := VerifyOtpVerificationToken("header.payload.signature", "invalid_hex")
	if err == nil {
		t.Error("Expected error when using invalid hex key, got nil")
	}
}
