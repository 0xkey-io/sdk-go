package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SessionClaims contains identity and profile-binding claims from a verified
// session JWT. Authorization scope is deliberately absent: callers must resolve
// the referenced SessionProfile on the server and must not trust a token scope.
type SessionClaims struct {
	UserID           string
	OrganizationID   string
	SessionType      string
	PublicKey        string
	ExpiresAt        int64
	SessionProfileID string
	// UntrustedScope is decoded for Turnkey wire compatibility only. Callers
	// must resolve the Session Profile on the server before authorizing.
	UntrustedScope string
}

// VerifyAndDecodeSessionClaims verifies the JWT signature before exposing its
// claims. The optional public-key override is intended for tests and non-production
// notarizers, matching VerifySessionJwtSignature.
//
//nolint:gocyclo // Alias conflict checks are intentionally explicit fail-closed validation.
func VerifyAndDecodeSessionClaims(jwtString string, dangerouslyOverrideNotarizerPublicKey ...string) (*SessionClaims, error) {
	if err := VerifySessionJwtSignature(jwtString, dangerouslyOverrideNotarizerPublicKey...); err != nil {
		return nil, fmt.Errorf("verify session JWT: %w", err)
	}
	parts := strings.Split(jwtString, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode session JWT payload: %w", err)
	}
	var raw struct {
		Subject               string `json:"sub"`
		UserID                string `json:"user_id"`
		Organization          string `json:"org"`
		OrganizationID        string `json:"organization_id"`
		Type                  string `json:"type"`
		SessionType           string `json:"session_type"`
		PublicKey             string `json:"pub"`
		LegacyPublicKey       string `json:"public_key"`
		ExpiresAt             int64  `json:"exp"`
		SessionProfileID      string `json:"session_profile_id"`
		CamelSessionProfileID string `json:"sessionProfileId"`
		Scope                 string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("decode session JWT claims: %w", err)
	}
	userID, err := claimAlias("user", raw.Subject, raw.UserID)
	if err != nil {
		return nil, err
	}
	organizationID, err := claimAlias("organization", raw.Organization, raw.OrganizationID)
	if err != nil {
		return nil, err
	}
	sessionType, err := claimAlias("session type", raw.Type, raw.SessionType)
	if err != nil {
		return nil, err
	}
	publicKey, err := claimAlias("public key", raw.PublicKey, raw.LegacyPublicKey)
	if err != nil {
		return nil, err
	}
	profileID, err := claimAlias("session profile", raw.SessionProfileID, raw.CamelSessionProfileID)
	if err != nil {
		return nil, err
	}
	if userID == "" || organizationID == "" || raw.ExpiresAt == 0 {
		return nil, fmt.Errorf("session JWT is missing required identity or expiry claims")
	}
	return &SessionClaims{
		UserID: userID, OrganizationID: organizationID, SessionType: sessionType,
		PublicKey: publicKey, ExpiresAt: raw.ExpiresAt, SessionProfileID: profileID,
		UntrustedScope: raw.Scope,
	}, nil
}

func claimAlias(name, compact, legacy string) (string, error) {
	if compact != "" && legacy != "" && compact != legacy {
		return "", fmt.Errorf("session JWT has conflicting %s claims", name)
	}
	if compact != "" {
		return compact, nil
	}
	return legacy, nil
}
