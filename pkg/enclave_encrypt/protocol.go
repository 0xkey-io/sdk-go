package enclave_encrypt

import (
	"github.com/cloudflare/circl/kem"

	"github.com/0xkey-io/sdk-go/internal/enclave"
)

func sealToTarget(receiver *kem.PublicKey, plaintext []byte) (ciphertext Bytes, encappedPublic []byte, err error) {
	ciphertextBytes, encapped, err := enclave.Encrypt(receiver, plaintext)
	if err != nil {
		return nil, nil, err
	}

	return Bytes(ciphertextBytes), encapped, nil
}

func openFromSender(encappedPublic Bytes, receiverPrivate kem.PrivateKey, ciphertext Bytes) ([]byte, error) {
	return enclave.Decrypt(encappedPublic, ciphertext, receiverPrivate)
}
