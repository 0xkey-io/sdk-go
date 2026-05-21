package enclave

import (
	"encoding/hex"
	"encoding/json"
)

type hexBytes []byte

func (bytes hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(bytes))
}

func (bytes *hexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}

	*bytes = b

	return nil
}
