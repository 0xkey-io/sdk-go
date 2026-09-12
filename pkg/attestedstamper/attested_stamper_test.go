package attestedstamper_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/0xkey-io/sdk-go/pkg/attestedstamper"
)

type vector struct {
	Header     string `json:"header"`
	Body       string `json:"bodyUtf8"`
	PublicKey  string `json:"publicKey"`
	HighDERHex string `json:"highDerHex"`
	LowDERHex  string `json:"lowDerHex"`
}

type recordingSigner struct {
	signature string
	got       []byte
}

type staticSigner struct{ signature string }

func (s staticSigner) Sign([]byte, string) (string, error) { return s.signature, nil }

func (s *recordingSigner) Sign(payload []byte, publicKey string) (string, error) {
	s.got = append([]byte(nil), payload...)
	return s.signature, nil
}

func TestStampMatchesSharedTurnkeyVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "turnkey-attested-stamp.json"))
	require.NoError(t, err)
	digest := sha256.Sum256(raw)
	require.Equal(t, "54d576e55629ae628df762354af91f630d5ce275aa3d5b78423dfe78f4d5661a", hex.EncodeToString(digest[:])) // gitleaks:allow
	var v vector
	require.NoError(t, json.Unmarshal(raw, &v))

	signer := &recordingSigner{signature: v.HighDERHex}
	stamper := attestedstamper.New(signer)
	require.NoError(t, stamper.Configure(attestedstamper.Config{
		AttestedIdentity: "verification-token",
		PublicKey:        v.PublicKey,
		Scheme:           attestedstamper.SchemeP256VerificationToken,
	}))

	stamp, err := stamper.Stamp([]byte(v.Body))
	require.NoError(t, err)
	require.Equal(t, v.Header, stamp.HeaderName)
	require.NotContains(t, stamp.HeaderValue, "=")
	require.Equal(t, []byte(v.Body), signer.got)

	decoded, err := base64.RawURLEncoding.DecodeString(stamp.HeaderValue)
	require.NoError(t, err)
	var payload map[string]string
	require.NoError(t, json.Unmarshal(decoded, &payload))
	require.Equal(t, map[string]string{
		"publicKeyAttestation": "verification-token",
		"scheme":               string(attestedstamper.SchemeP256VerificationToken),
		"publicKey":            v.PublicKey,
		"signature":            v.LowDERHex,
	}, payload)
}

func TestStampFailsClosedAndConfigRejectsAmbiguousIdentity(t *testing.T) {
	stamper := attestedstamper.New(&recordingSigner{})
	_, err := stamper.Stamp([]byte("{}"))
	require.ErrorContains(t, err, "not configured")

	err = stamper.Configure(attestedstamper.Config{
		AttestedIdentity: "token",
		PublicKey:        "key",
		Scheme:           "unknown",
	})
	require.ErrorContains(t, err, "unsupported attested scheme")
}

func TestOIDCSignsMutatedBodyWithoutLeakingIdentity(t *testing.T) {
	signer := &recordingSigner{signature: "30440220010101010101010101010101010101010101010101010101010101010101010102200101010101010101010101010101010101010101010101010101010101010101"}
	stamper := attestedstamper.New(signer)
	require.NoError(t, stamper.Configure(attestedstamper.Config{
		AttestedIdentity: "secret-oidc-token",
		PublicKey:        "public-key",
		Scheme:           attestedstamper.SchemeP256OIDC,
	}))

	_, err := stamper.Stamp([]byte("{\"body\":1} "))
	require.NoError(t, err)
	require.Equal(t, []byte("{\"body\":1} "), signer.got)
	require.NotContains(t, fmt.Sprintf("%+v", stamper), "secret-oidc-token")

	stamper.Clear()
	_, err = stamper.Stamp([]byte("{}"))
	require.ErrorContains(t, err, "not configured")
}

//nolint:gocyclo // Each concurrent failure is reported without calling FailNow from a worker goroutine.
func TestConcurrentConfigureAndStampNeverMixesIdentityAndKey(t *testing.T) {
	signature := "30440220010101010101010101010101010101010101010101010101010101010101010102200101010101010101010101010101010101010101010101010101010101010101"
	stamper := attestedstamper.New(staticSigner{signature: signature})
	configs := []attestedstamper.Config{
		{AttestedIdentity: "identity-a", PublicKey: "key-a", Scheme: attestedstamper.SchemeP256OIDC},
		{AttestedIdentity: "identity-b", PublicKey: "key-b", Scheme: attestedstamper.SchemeP256VerificationToken},
	}
	require.NoError(t, stamper.Configure(configs[0]))

	var workers sync.WaitGroup
	errors := make(chan error, 8)
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(offset int) {
			defer workers.Done()
			for i := 0; i < 250; i++ {
				if err := stamper.Configure(configs[(i+offset)%len(configs)]); err != nil {
					errors <- err
					return
				}
				stamp, err := stamper.Stamp([]byte("{}"))
				if err != nil {
					errors <- err
					return
				}
				decoded, err := base64.RawURLEncoding.DecodeString(stamp.HeaderValue)
				if err != nil {
					errors <- err
					return
				}
				var payload map[string]string
				if err := json.Unmarshal(decoded, &payload); err != nil {
					errors <- err
					return
				}
				validPair := (payload["publicKeyAttestation"] == "identity-a" && payload["publicKey"] == "key-a") ||
					(payload["publicKeyAttestation"] == "identity-b" && payload["publicKey"] == "key-b")
				if !validPair {
					errors <- fmt.Errorf("mixed identity/key pair: %v", payload)
					return
				}
			}
		}(worker)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}
