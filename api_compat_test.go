// Package sdk_test freezes the public API surface of github.com/0xkey-io/sdk-go.
// Compile failures here indicate a breaking API change.
package sdk_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/golang-jwt/jwt/v5"

	sdk "github.com/0xkey-io/sdk-go"
	"github.com/0xkey-io/sdk-go/pkg/api/client"
	"github.com/0xkey-io/sdk-go/pkg/api/models"
	"github.com/0xkey-io/sdk-go/pkg/apikey"
	"github.com/0xkey-io/sdk-go/pkg/common"
	"github.com/0xkey-io/sdk-go/pkg/crypto"
	"github.com/0xkey-io/sdk-go/pkg/enclave_encrypt"
	"github.com/0xkey-io/sdk-go/pkg/encryptionkey"
	"github.com/0xkey-io/sdk-go/pkg/proofs"
	"github.com/0xkey-io/sdk-go/pkg/store"
	"github.com/0xkey-io/sdk-go/pkg/store/local"
)

// --- root sdk: strict function signatures ---

var (
	_ func(...sdk.OptionFunc) (*sdk.Client, error)      = sdk.New
	_ func(sdk.Logger) sdk.OptionFunc                   = sdk.WithLogger
	_ func(string) sdk.OptionFunc                       = sdk.WithClientVersion
	_ func(strfmt.Registry) sdk.OptionFunc              = sdk.WithRegistry
	_ func(client.TransportConfig) sdk.OptionFunc       = sdk.WithTransportConfig
	_ func(*apikey.Key) sdk.OptionFunc                  = sdk.WithAPIKey
	_ func(string) sdk.OptionFunc                       = sdk.WithAPIKeyName
	_ func(strfmt.Registry) *client.ZeroXKeyAPI         = sdk.NewHTTPClient
	_ func(http.RoundTripper, string) http.RoundTripper = sdk.SetClientVersion
)

// --- pkg/apikey ---

var _ common.IKey[apikey.Metadata] = (*apikey.Key)(nil)

var (
	_                                               = apikey.New
	_                                               = apikey.WithScheme
	_                                               = apikey.FromZeroXKeyPrivateKey
	_                                               = apikey.FromECDSAPrivateKey
	_                                               = apikey.DecodeZeroXKeyPublicECDSAKey
	_                                               = apikey.ExtractSignatureSchemeFromSuffixedPrivateKey
	_ func([]byte, *apikey.Key) (string, error)     = apikey.Stamp
	_ func(*ecdsa.PrivateKey) string                = apikey.EncodePrivateECDSAKey
	_ func(*ecdsa.PublicKey) string                 = apikey.EncodePublicECDSAKey
	_ func(ed25519.PrivateKey) (*apikey.Key, error) = apikey.FromED25519PrivateKey
	_                                               = apikey.ZeroXKeyECDSAPublicKeyBytes
	_ apikey.Curve                                  = apikey.CurveP256
	_ apikey.Curve                                  = apikey.CurveSecp256k1
	_ apikey.Curve                                  = apikey.CurveEd25519
)

// --- pkg/encryptionkey ---

var _ common.IKey[encryptionkey.Metadata] = (*encryptionkey.Key)(nil)

var (
	_ func(string, string) (*encryptionkey.Key, error) = encryptionkey.New
	_ func(kem.PrivateKey) (string, error)             = encryptionkey.EncodePrivateKey
	_ func(kem.PublicKey) (string, error)              = encryptionkey.EncodePublicKey
	_ func(kem.PrivateKey) (*encryptionkey.Key, error) = encryptionkey.FromKemPrivateKey
	_ func(string) (*encryptionkey.Key, error)         = encryptionkey.FromZeroXKeyPrivateKey
	_ func(string) (*kem.PrivateKey, error)            = encryptionkey.DecodeZeroXKeyPrivateKey
	_ func(string) (*kem.PublicKey, error)             = encryptionkey.DecodeZeroXKeyPublicKey
)

// --- pkg/enclave_encrypt ---

var (
	_ func(*ecdsa.PublicKey) (*enclave_encrypt.EnclaveEncryptClient, error)                                   = enclave_encrypt.NewEnclaveEncryptClient
	_ func(*ecdsa.PublicKey, kem.PrivateKey) (*enclave_encrypt.EnclaveEncryptClient, error)                   = enclave_encrypt.NewEnclaveEncryptClientFromTargetKey
	_ func(*ecdsa.PrivateKey, string, *string) (enclave_encrypt.EnclaveEncryptServer, error)                  = enclave_encrypt.NewEnclaveEncryptServer
	_ func(*ecdsa.PrivateKey, *kem.PrivateKey, string, *string) (enclave_encrypt.EnclaveEncryptServer, error) = enclave_encrypt.NewEnclaveEncryptServerFromTargetKey
	_ func(*ecdsa.PrivateKey, []byte) ([]byte, error)                                                         = enclave_encrypt.P256Sign
	_ func(*ecdsa.PublicKey, []byte, []byte) bool                                                             = enclave_encrypt.P256Verify
	_ func([]byte) (*ecdsa.PublicKey, error)                                                                  = enclave_encrypt.ToEcdsaPublic
	_ func([]byte) error                                                                                      = enclave_encrypt.ValidateChecksum
)

// --- pkg/crypto ---

var (
	_ func(string, ...string) error                   = crypto.VerifySessionJwtSignature
	_ func(string, string, ...jwt.ParserOption) error = crypto.VerifyOtpVerificationToken
)

// --- pkg/store ---

var (
	_ store.Store[*apikey.Key, apikey.Metadata]               = (*local.Store[*apikey.Key, apikey.Metadata])(nil)
	_ store.Store[*encryptionkey.Key, encryptionkey.Metadata] = (*local.Store[*encryptionkey.Key, encryptionkey.Metadata])(nil)
)

// --- pkg/proofs ---

var (
	_ func(*models.AppProof, *models.BootProof) error = proofs.Verify
	_ func(*models.AppProof) error                    = proofs.VerifyAppProofSignature
	_ func(*models.BootProof) (time.Time, error)      = proofs.GetBootProofTime
)

// --- sdk.Client methods ---

type clientAPI interface {
	DefaultOrganization() *string
	V0() *client.ZeroXKeyAPI
}

type authenticatorAPI interface {
	AuthenticateRequest(runtime.ClientRequest, strfmt.Registry) error
}

var (
	_ clientAPI        = (*sdk.Client)(nil)
	_ authenticatorAPI = (*sdk.Authenticator)(nil)
)

// --- exported types ---

var (
	_ sdk.Logger
	_ sdk.OptionFunc
	_ sdk.Client
	_ sdk.Authenticator
	_ apikey.Metadata
	_ apikey.Key
	_ apikey.APIStamp
	_ encryptionkey.Metadata
	_ encryptionkey.Key
)

// --- wire constants (compile-time string identity) ---

const (
	wireSchemeP256      = "SIGNATURE_SCHEME_TK_API_P256"
	wireSchemeSecp256k1 = "SIGNATURE_SCHEME_TK_API_SECP256K1"
	wireSchemeEd25519   = "SIGNATURE_SCHEME_TK_API_ED25519"
	wireHpkeInfo        = "0xkey_hpke"
	wireBundleVersion   = "v1.0.0"
)

var (
	_ = wireSchemeP256 == string(apikey.SchemeP256)
	_ = wireSchemeSecp256k1 == string(apikey.SchemeSECP256K1)
	_ = wireSchemeEd25519 == string(apikey.SchemeED25519)
	_ = wireHpkeInfo == enclave_encrypt.ZeroXKeyHpkeInfo
	_ = wireBundleVersion == enclave_encrypt.DataVersion
)
