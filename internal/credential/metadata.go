package credential

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
)

// LoadJSONMetadata reads metadata from a JSON file into dest.
func LoadJSONMetadata[T any](path string, dest *T) (*T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open metadata file")
	}
	defer f.Close() //nolint: errcheck

	if err := json.NewDecoder(f).Decode(dest); err != nil {
		return nil, errors.Wrap(err, "failed to decode metadata file")
	}

	return dest, nil
}
