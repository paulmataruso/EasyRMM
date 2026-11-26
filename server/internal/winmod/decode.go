package winmod

import (
	"bytes"
	"encoding/json"
	"errors"
)

// DecodeStrict reads data into v with no unknown field and nothing after it: how a catalog entry's own decoder
// reads a result it then changes before storing (Typed is the plain case).
func DecodeStrict(data json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return errors.New("the data does not match the action's result schema")
	}
	return nil
}
