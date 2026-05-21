package sdk_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xkey-io/sdk-go/pkg/apikey"
	"github.com/0xkey-io/sdk-go/pkg/enclave_encrypt"
)

func TestWireSchemeConstantsGolden(t *testing.T) {
	assert.Equal(t, "SIGNATURE_SCHEME_TK_API_P256", string(apikey.SchemeP256))
	assert.Equal(t, "SIGNATURE_SCHEME_TK_API_SECP256K1", string(apikey.SchemeSECP256K1))
	assert.Equal(t, "SIGNATURE_SCHEME_TK_API_ED25519", string(apikey.SchemeED25519))
	assert.Equal(t, "0xkey_hpke", enclave_encrypt.ZeroXKeyHpkeInfo)
	assert.Equal(t, "v1.0.0", enclave_encrypt.DataVersion)
}

func TestStampJSONGolden(t *testing.T) {
	const (
		encodedPrivateKey = "3514c6f83c8fb2facfd1947d6332d8f38512dd945f3cb87b9b6ea3b877b564388ba00e7ee515fc82b53d525802d3769d66a0e1cc8b9927b6ca854d1a1e7d3211"
		goldenPublicKey   = "8ba00e7ee515fc82b53d525802d3769d66a0e1cc8b9927b6ca854d1a1e7d3211"
		goldenSignature   = "fb8d09d2fa817ac0f99c99c3a65a2a8ea2a4c9b95008c22b4ba79a7d0227ed65f832234491a588f827fa33dbdda5bb47537be0166729d0f9f4d1f20d8e61b405"
		message           = "MESSAGE"
	)

	key, err := apikey.FromZeroXKeyPrivateKey(encodedPrivateKey, apikey.SchemeED25519)
	require.NoError(t, err)

	stampHeader, err := apikey.Stamp([]byte(message), key)
	require.NoError(t, err)

	decoded, err := base64.RawURLEncoding.DecodeString(stampHeader)
	require.NoError(t, err)

	var stamp apikey.APIStamp
	require.NoError(t, json.Unmarshal(decoded, &stamp))

	assert.Equal(t, goldenPublicKey, stamp.PublicKey)
	assert.Equal(t, "SIGNATURE_SCHEME_TK_API_ED25519", string(stamp.Scheme))
	assert.Equal(t, goldenSignature, stamp.Signature)

	pubKeyBytes, err := hex.DecodeString(goldenPublicKey)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(message), mustHexDecode(t, goldenSignature)))
}

// TestHPKEBundleRoundTripV1 exercises the v1 bundle wire format end-to-end:
// the server publishes a target bundle, the client encrypts to it, and the
// server decrypts the resulting ClientSendMsg. The intent is to lock down the
// v1 envelope shape (fields, version string) and the encrypt/decrypt contract.
func TestHPKEBundleRoundTripV1(t *testing.T) {
	const (
		orgID  = "f412ea93-998b-45a5-9df8-d2797c7f1a67"
		userID = "4eb08a82-00ee-4f29-b076-fca769209725"
	)

	authKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	server, err := enclave_encrypt.NewEnclaveEncryptServer(authKey, orgID, ptr(userID))
	require.NoError(t, err)

	targetBundle, err := server.PublishTarget()
	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", targetBundle.Version)

	bundleBytes, err := json.Marshal(targetBundle)
	require.NoError(t, err)

	client, err := enclave_encrypt.NewEnclaveEncryptClient(&authKey.PublicKey)
	require.NoError(t, err)

	msg, err := client.Encrypt([]byte("golden plaintext"), bundleBytes, orgID, userID)
	require.NoError(t, err)
	require.NotNil(t, msg.EncappedPublic)
	require.NotNil(t, msg.Ciphertext)

	serverRecv := server.IntoEnclaveServerRecv()
	plaintext, err := serverRecv.Decrypt(*msg)
	require.NoError(t, err)
	assert.Equal(t, []byte("golden plaintext"), plaintext)
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

func ptr(s string) *string {
	return &s
}
