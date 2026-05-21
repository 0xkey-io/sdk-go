package encryptionkey_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xkey-io/sdk-go/pkg/encryptionkey"
)

func Test_EncodedKeySizeIsFixed(t *testing.T) {
	for i := 0; i < 100; i++ {
		encryptionKey, err := encryptionkey.New(uuid.NewString(), uuid.NewString())
		require.NoError(t, err)

		assert.Len(t, encryptionKey.EncodedPublicKey, 130, "attempt %d: expected 130 characters for public key %s", i, encryptionKey.EncodedPublicKey)
		assert.Len(t, encryptionKey.EncodedPrivateKey, 64, "attempt %d: expected 64 characters for private key %s", i, encryptionKey.EncodedPrivateKey)
	}
}

func Test_MetadataMergeWorks(t *testing.T) {
	k, err := encryptionkey.New(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	assert.Equal(t, "", k.GetMetadata().Name)

	err = k.MergeMetadata(encryptionkey.Metadata{
		Name:      "Custom Name",
		PublicKey: k.EncodedPublicKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "Custom Name", k.GetMetadata().Name)
}
