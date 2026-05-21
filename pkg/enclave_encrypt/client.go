package enclave_encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cloudflare/circl/kem"

	"github.com/0xkey-io/sdk-go/internal/enclave"
)

// An instance of the client side for enclave encrypt protocol. This should only be used for either
// a SINGLE send or a single receive.
type EnclaveEncryptClient struct {
	enclaveAuthKey *ecdsa.PublicKey
	targetPrivate  kem.PrivateKey
}

// Create a client from the quorum public key.
func NewEnclaveEncryptClient(enclaveAuthKey *ecdsa.PublicKey) (*EnclaveEncryptClient, error) {
	_, targetPrivate, err := KemId.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &EnclaveEncryptClient{
		enclaveAuthKey: enclaveAuthKey,
		targetPrivate:  targetPrivate,
	}, nil
}

// Create a client from the quorum public key and target key pair.
func NewEnclaveEncryptClientFromTargetKey(enclaveAuthKey *ecdsa.PublicKey, targetPrivateKey kem.PrivateKey) (*EnclaveEncryptClient, error) {
	return &EnclaveEncryptClient{
		enclaveAuthKey: enclaveAuthKey,
		targetPrivate:  targetPrivateKey,
	}, nil
}

// Encrypt some plaintext to the given server, using `enclaveMsgBytes`.
func (c *EnclaveEncryptClient) Encrypt(plaintext Bytes, bundleBytes Bytes, organizationId string, userId string) (*ClientSendMsg, error) {
	targetPublic, err := enclave.DecodeTargetBundle(bundleBytes, c.enclaveAuthKey, organizationId, userId)
	if err != nil {
		return nil, err
	}

	ciphertext, encappedPublic, err := sealToTarget(&targetPublic, plaintext)
	if err != nil {
		return nil, err
	}

	enc := Bytes(encappedPublic)

	return &ClientSendMsg{
		EncappedPublic: &enc,
		Ciphertext:     &ciphertext,
	}, nil
}

// Decrypts a bundle. This is used in private key and wallet export flows.
func (c *EnclaveEncryptClient) Decrypt(bundleBytes Bytes, organizationId string) ([]byte, error) {
	encappedPublic, ciphertext, err := enclave.DecodeSendBundle(bundleBytes, c.enclaveAuthKey, organizationId)
	if err != nil {
		return nil, err
	}

	return openFromSender(encappedPublic, c.targetPrivate, ciphertext)
}

// Get this clients target public key.
func (c *EnclaveEncryptClient) TargetPublic() ([]byte, error) {
	return c.targetPrivate.Public().MarshalBinary()
}

// Decrypt a base58-encoded payload from the server. This is used in email authentication and email recovery flows.
func (c *EnclaveEncryptClient) AuthDecrypt(payload string) ([]byte, error) {
	payloadBytes := base58.Decode(payload)

	if err := ValidateChecksum(payloadBytes); err != nil {
		return nil, err
	}

	payloadBytes = payloadBytes[:len(payloadBytes)-4]
	if len(payloadBytes) < 33 {
		return nil, errors.New("payload is less then 33 bytes, the length of the expected public key")
	}

	compressedKey := payloadBytes[0:33]
	ciphertext := payloadBytes[33:]

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressedKey)
	//nolint:staticcheck
	encappedPublic := elliptic.Marshal(elliptic.P256(), x, y)

	return openFromSender(encappedPublic, c.targetPrivate, ciphertext)
}
