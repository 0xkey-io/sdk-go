package credential

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
)

// StampPayload is the wire-format JSON object placed in the X-Stamp header.
type StampPayload struct {
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Scheme    string `json:"scheme"`
}

// EncodeStamp signs message with signer and returns a base64url-encoded stamp.
func EncodeStamp(message []byte, signer Signer) (string, error) {
	signature, err := signer.Sign(message)
	if err != nil {
		return "", err
	}

	payload := StampPayload{
		PublicKey: signer.PublicKeyHex(),
		Signature: signature,
		Scheme:    signer.Scheme(),
	}

	jsonStamp, err := json.Marshal(payload)
	if err != nil {
		return "", errors.Wrap(err, "failed to encode API stamp as JSON")
	}

	return base64.RawURLEncoding.EncodeToString(jsonStamp), nil
}
