package credential

// Signer signs API request payloads for authentication stamps.
type Signer interface {
	Sign(message []byte) (signatureHex string, err error)
	PublicKeyHex() string
	Scheme() string
}
