package enclave

import (
	"github.com/cloudflare/circl/hpke"
)

const (
	KemID       hpke.KEM  = hpke.KEM_P256_HKDF_SHA256
	KdfID       hpke.KDF  = hpke.KDF_HKDF_SHA256
	AeadID      hpke.AEAD = hpke.AEAD_AES256GCM
	HpkeInfo    string    = "0xkey_hpke"
	DataVersion           = "v1.0.0"
)
