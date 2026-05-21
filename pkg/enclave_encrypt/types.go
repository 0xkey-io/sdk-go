package enclave_encrypt

import (
	"encoding/hex"
	"encoding/json"

	"github.com/cloudflare/circl/hpke"

	"github.com/0xkey-io/sdk-go/internal/enclave"
)

// HPKE suite parameters and protocol-level constants for the 0xkey enclave wire format.
// These are part of the public wire protocol and must not change without coordinating
// with the enclave/server side.
const (
	// KemId is the HPKE Key Encapsulation Mechanism used by the enclave protocol.
	KemId hpke.KEM = enclave.KemID
	// KdfId is the HPKE Key Derivation Function used by the enclave protocol.
	KdfId hpke.KDF = enclave.KdfID
	// AeadId is the HPKE AEAD cipher used by the enclave protocol.
	AeadId hpke.AEAD = enclave.AeadID
	// ZeroXKeyHpkeInfo is the HPKE info string bound into the protocol context.
	ZeroXKeyHpkeInfo string = enclave.HpkeInfo
	// DataVersion is the current bundle data version emitted by the enclave.
	DataVersion string = enclave.DataVersion
)

// Bytes is a byte slice that marshals to/from a hex-encoded JSON string.
type Bytes []byte

// MarshalJSON implements json.Marshaler by hex-encoding the underlying bytes.
func (bytes Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(bytes))
}

// UnmarshalJSON implements json.Unmarshaler by hex-decoding the JSON string.
func (bytes *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}

	*bytes = b

	return nil
}

// ServerMsg carries only the bundle version and is used to dispatch to the
// concrete bundle struct (V0 vs V1).
type ServerMsg struct {
	// Version of the data; nil indicates a V0 bundle.
	Version *string `json:"version,omitempty"`
}

// ServerSendMsgV0 is the legacy server->client envelope used before signed-data bundles.
// It carries the encapsulated key, an enclave signature over that key, and the ciphertext.
type ServerSendMsgV0 struct {
	// EncappedPublic is the HPKE encapsulated public key used to derive the shared secret.
	EncappedPublic *Bytes `json:"encappedPublic,omitempty"`
	// EncappedPublicSignature is the enclave quorum signature over EncappedPublic.
	EncappedPublicSignature *Bytes `json:"encappedPublicSignature,omitempty"`
	// Ciphertext is the AEAD ciphertext produced by the enclave.
	Ciphertext *Bytes `json:"ciphertext,omitempty"`
}

// ServerSendMsgV1 is the current server->client envelope: a versioned, signed
// blob plus the enclave quorum public key used to verify it.
type ServerSendMsgV1 struct {
	// Version of the data payload.
	Version string `json:"version"`
	// Data is the JSON-encoded ServerSendData payload.
	Data Bytes `json:"data"`
	// DataSignature is the enclave quorum signature over Data.
	DataSignature Bytes `json:"dataSignature"`
	// EnclaveQuorumPublic is the uncompressed P-256 quorum public key.
	EnclaveQuorumPublic Bytes `json:"enclaveQuorumPublic"`
}

// ServerSendData is the JSON payload signed by the enclave quorum and carried
// inside ServerSendMsgV1.Data.
type ServerSendData struct {
	// EncappedPublic is the HPKE encapsulated public key.
	EncappedPublic Bytes `json:"encappedPublic"`
	// Ciphertext is the AEAD ciphertext.
	Ciphertext Bytes `json:"ciphertext"`
	// OrganizationId binds the payload to a specific organization.
	OrganizationId string `json:"organizationId"`
}

// ServerTargetMsgV0 is the legacy server->client target-key publishing envelope.
type ServerTargetMsgV0 struct {
	// TargetPublic is the enclave's target public key clients should encrypt to.
	TargetPublic Bytes `json:"targetPublic"`
	// TargetPublicSignature is the enclave quorum signature over TargetPublic.
	TargetPublicSignature Bytes `json:"targetPublicSignature"`
}

// ServerTargetMsgV1 is the current target-key publishing envelope: a versioned,
// signed payload plus the enclave quorum public key used to verify it.
type ServerTargetMsgV1 struct {
	// Version of the data payload.
	Version string `json:"version"`
	// Data is the JSON-encoded ServerTargetData payload.
	Data Bytes `json:"data"`
	// DataSignature is the enclave quorum signature over Data.
	DataSignature Bytes `json:"dataSignature"`
	// EnclaveQuorumPublic is the uncompressed P-256 quorum public key.
	EnclaveQuorumPublic Bytes `json:"enclaveQuorumPublic"`
}

// ServerTargetData is the JSON payload signed by the enclave quorum and
// carried inside ServerTargetMsgV1.Data.
type ServerTargetData struct {
	// TargetPublic is the enclave's target public key clients should encrypt to.
	TargetPublic Bytes `json:"targetPublic"`
	// OrganizationId binds the target key to a specific organization.
	OrganizationId string `json:"organizationId"`
	// UserId binds the target key to a specific user within the organization.
	UserId string `json:"userId"`
}

// ClientSendMsg is the client->server envelope produced by EnclaveEncryptClient.Encrypt.
// The pair (EncappedPublic, Ciphertext) forms the HPKE single-shot output.
type ClientSendMsg struct {
	// EncappedPublic is the HPKE encapsulated public key.
	EncappedPublic *Bytes `json:"encappedPublic,omitempty"`
	// Ciphertext is the AEAD ciphertext to be decrypted by the enclave.
	Ciphertext *Bytes `json:"ciphertext,omitempty"`
}
