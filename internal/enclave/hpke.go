package enclave

import (
	"crypto/rand"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// Encrypt seals plaintext to receiver using HPKE.
func Encrypt(receiver *kem.PublicKey, plaintext []byte) (ciphertext, encappedPublic []byte, err error) {
	suite := hpke.NewSuite(KemID, KdfID, AeadID)

	sender, err := suite.NewSender(*receiver, []byte(HpkeInfo))
	if err != nil {
		return nil, nil, err
	}

	encappedPublic, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	aad, err := additionalAssociatedData(*receiver, encappedPublic)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err = sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, encappedPublic, nil
}

// Decrypt opens ciphertext using the receiver private key and encapsulated sender key.
func Decrypt(encappedPublic, ciphertext []byte, receiverPrivate kem.PrivateKey) ([]byte, error) {
	suite := hpke.NewSuite(KemID, KdfID, AeadID)

	receiver, err := suite.NewReceiver(receiverPrivate, []byte(HpkeInfo))
	if err != nil {
		return nil, err
	}

	opener, err := receiver.Setup(encappedPublic)
	if err != nil {
		return nil, err
	}

	aad, err := additionalAssociatedData(receiverPrivate.Public(), encappedPublic)
	if err != nil {
		return nil, err
	}

	return opener.Open(ciphertext, aad)
}

func additionalAssociatedData(receiverPublic kem.PublicKey, senderPublic []byte) ([]byte, error) {
	receiverPublicBytes, err := receiverPublic.MarshalBinary()
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, len(senderPublic)+len(receiverPublicBytes))
	result = append(result, senderPublic...)
	result = append(result, receiverPublicBytes...)

	return result, nil
}
