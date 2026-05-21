package enclave

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"

	"github.com/0xkey-io/sdk-go/internal/p256util"
)

// TargetDecoder extracts a target public key from a server bundle.
type TargetDecoder interface {
	DecodeTarget(bundleJSON []byte, authKey *ecdsa.PublicKey, organizationID, userID string) (kem.PublicKey, error)
}

// SendDecoder extracts ciphertext material from a server send bundle.
type SendDecoder interface {
	DecodeSend(bundleJSON []byte, authKey *ecdsa.PublicKey, organizationID string) (encappedPublic, ciphertext []byte, err error)
}

type envelope struct {
	Version *string `json:"version,omitempty"`
}

type targetDecoderV0 struct{}

type targetDecoderV1 struct{}

type sendDecoderV0 struct{}

type sendDecoderV1 struct{}

var (
	targetDecoders = map[string]TargetDecoder{
		"":          targetDecoderV0{},
		DataVersion: targetDecoderV1{},
	}
	sendDecoders = map[string]SendDecoder{
		"":          sendDecoderV0{},
		DataVersion: sendDecoderV1{},
	}
)

// DecodeTargetBundle selects the appropriate codec and returns the target KEM key.
func DecodeTargetBundle(bundleJSON []byte, authKey *ecdsa.PublicKey, organizationID, userID string) (kem.PublicKey, error) {
	version, err := bundleVersion(bundleJSON)
	if err != nil {
		return nil, err
	}

	decoder, ok := targetDecoders[versionKey(version)]
	if !ok {
		return nil, fmt.Errorf("invalid data version: %v", version)
	}

	return decoder.DecodeTarget(bundleJSON, authKey, organizationID, userID)
}

// DecodeSendBundle selects the appropriate codec and returns ciphertext material.
func DecodeSendBundle(bundleJSON []byte, authKey *ecdsa.PublicKey, organizationID string) (encappedPublic, ciphertext []byte, err error) {
	version, err := bundleVersion(bundleJSON)
	if err != nil {
		return nil, nil, err
	}

	decoder, ok := sendDecoders[versionKey(version)]
	if !ok {
		return nil, nil, fmt.Errorf("invalid data version: %v", version)
	}

	return decoder.DecodeSend(bundleJSON, authKey, organizationID)
}

func bundleVersion(bundleJSON []byte) (*string, error) {
	var env envelope
	if err := json.Unmarshal(bundleJSON, &env); err != nil {
		return nil, err
	}

	return env.Version, nil
}

func versionKey(version *string) string {
	if version == nil {
		return ""
	}

	return *version
}

// --- V0 target ---

type targetMsgV0 struct {
	TargetPublic          hexBytes `json:"targetPublic"`
	TargetPublicSignature hexBytes `json:"targetPublicSignature"`
}

func (targetDecoderV0) DecodeTarget(bundleJSON []byte, authKey *ecdsa.PublicKey, _, _ string) (kem.PublicKey, error) {
	var msg targetMsgV0
	if err := json.Unmarshal(bundleJSON, &msg); err != nil {
		return nil, err
	}

	if !p256util.VerifyASN1(authKey, msg.TargetPublic, msg.TargetPublicSignature) {
		return nil, errors.New("invalid enclave auth key signature")
	}

	return KemID.Scheme().UnmarshalBinaryPublicKey(msg.TargetPublic)
}

// --- V1 target ---

type targetMsgV1 struct {
	Version             string   `json:"version"`
	Data                hexBytes `json:"data"`
	DataSignature       hexBytes `json:"dataSignature"`
	EnclaveQuorumPublic hexBytes `json:"enclaveQuorumPublic"`
}

type targetDataV1 struct {
	TargetPublic   hexBytes `json:"targetPublic"`
	OrganizationId string   `json:"organizationId"`
	UserId         string   `json:"userId"`
}

func (targetDecoderV1) DecodeTarget(bundleJSON []byte, authKey *ecdsa.PublicKey, organizationID, userID string) (kem.PublicKey, error) {
	var msg targetMsgV1
	if err := json.Unmarshal(bundleJSON, &msg); err != nil {
		return nil, err
	}

	if len(msg.EnclaveQuorumPublic) == 0 {
		return nil, errors.New("missing enclave quorum public key")
	}

	quorumKey, err := p256util.ParseUncompressedPublicKey(msg.EnclaveQuorumPublic)
	if err != nil {
		return nil, err
	}

	if !quorumKey.Equal(authKey) {
		return nil, errors.New("enclave quorum public keys from client and message do not match")
	}

	if !p256util.VerifyASN1(quorumKey, msg.Data, msg.DataSignature) {
		return nil, errors.New("invalid enclave auth key signature")
	}

	var signed targetDataV1
	if err := json.Unmarshal(msg.Data, &signed); err != nil {
		return nil, err
	}

	if signed.OrganizationId != organizationID {
		return nil, errors.New("organization id does not match expected value")
	}

	if signed.UserId != userID {
		return nil, errors.New("user id does not match expected value")
	}

	return KemID.Scheme().UnmarshalBinaryPublicKey(signed.TargetPublic)
}

// --- V0 send ---

type sendMsgV0 struct {
	EncappedPublic          *hexBytes `json:"encappedPublic,omitempty"`
	EncappedPublicSignature *hexBytes `json:"encappedPublicSignature,omitempty"`
	Ciphertext              *hexBytes `json:"ciphertext,omitempty"`
}

func (sendDecoderV0) DecodeSend(bundleJSON []byte, authKey *ecdsa.PublicKey, _ string) ([]byte, []byte, error) {
	var msg sendMsgV0
	if err := json.Unmarshal(bundleJSON, &msg); err != nil {
		return nil, nil, err
	}

	if msg.EncappedPublic == nil || msg.EncappedPublicSignature == nil || msg.Ciphertext == nil {
		return nil, nil, errors.New("missing send bundle fields")
	}

	if !p256util.VerifyASN1(authKey, *msg.EncappedPublic, *msg.EncappedPublicSignature) {
		return nil, nil, errors.New("invalid enclave auth key signature")
	}

	return *msg.EncappedPublic, *msg.Ciphertext, nil
}

// --- V1 send ---

type sendMsgV1 struct {
	Version             string   `json:"version"`
	Data                hexBytes `json:"data"`
	DataSignature       hexBytes `json:"dataSignature"`
	EnclaveQuorumPublic hexBytes `json:"enclaveQuorumPublic"`
}

type sendDataV1 struct {
	EncappedPublic hexBytes `json:"encappedPublic"`
	Ciphertext     hexBytes `json:"ciphertext"`
	OrganizationId string   `json:"organizationId"`
}

func (sendDecoderV1) DecodeSend(bundleJSON []byte, authKey *ecdsa.PublicKey, organizationID string) ([]byte, []byte, error) {
	var msg sendMsgV1
	if err := json.Unmarshal(bundleJSON, &msg); err != nil {
		return nil, nil, err
	}

	if len(msg.EnclaveQuorumPublic) == 0 {
		return nil, nil, errors.New("missing enclave quorum public key")
	}

	quorumKey, err := p256util.ParseUncompressedPublicKey(msg.EnclaveQuorumPublic)
	if err != nil {
		return nil, nil, err
	}

	if !quorumKey.Equal(authKey) {
		return nil, nil, errors.New("enclave quorum public keys from client and message do not match")
	}

	if !p256util.VerifyASN1(quorumKey, msg.Data, msg.DataSignature) {
		return nil, nil, errors.New("invalid enclave auth key signature")
	}

	var signed sendDataV1
	if err := json.Unmarshal(msg.Data, &signed); err != nil {
		return nil, nil, err
	}

	if signed.OrganizationId != organizationID {
		return nil, nil, errors.New("organization id does not match expected value")
	}

	return signed.EncappedPublic, signed.Ciphertext, nil
}
