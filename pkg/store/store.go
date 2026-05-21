// Package store defines a key storage interface.
package store

import (
	"github.com/pkg/errors"

	"github.com/0xkey-io/sdk-go/pkg/apikey"
	"github.com/0xkey-io/sdk-go/pkg/common"
	"github.com/0xkey-io/sdk-go/pkg/encryptionkey"
)

// Store provides an interface in which API or Encryption keys may be stored and retrieved.
type Store[T common.IKey[M], M common.IMetadata] interface {
	Load(name string) (T, error)
	Store(name string, key common.IKey[M]) error
}

// KeyFactory generic struct to select the correct FromZeroXKeyPrivateKey function.
type KeyFactory[T common.IKey[M], M common.IMetadata] struct{}

// FromZeroXKeyPrivateKey converts a 0xkey-encoded private key string to a key.
func (kf KeyFactory[T, M]) FromZeroXKeyPrivateKey(data string) (T, error) {
	var zero T

	switch any(zero).(type) {
	case *apikey.Key:
		keyWithoutSuffix, scheme, err := apikey.ExtractSignatureSchemeFromSuffixedPrivateKey(data)
		if err != nil {
			return zero, err
		}

		key, err := apikey.FromZeroXKeyPrivateKey(keyWithoutSuffix, scheme)
		if err != nil {
			return zero, err
		}

		result, ok := any(key).(T)
		if !ok {
			return zero, errors.Errorf("failed to convert apikey.Key to %T", zero)
		}

		return result, nil
	case *encryptionkey.Key:
		key, err := encryptionkey.FromZeroXKeyPrivateKey(data)
		if err != nil {
			return zero, err
		}

		result, ok := any(key).(T)
		if !ok {
			return zero, errors.Errorf("failed to convert encryptionkey.Key to %T", zero)
		}

		return result, nil
	default:
		return zero, errors.Errorf("unsupported key type: %T", zero)
	}
}
