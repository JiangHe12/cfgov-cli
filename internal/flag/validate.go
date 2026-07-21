package flag

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func DecodeSet(data []byte) ([]FeatureFlag, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, validationError("flags must be a JSON array", nil)
	}
	if data[0] != '[' {
		return nil, validationError("flags must be a JSON array", nil)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, validationError("flags must be a JSON array", err)
	}
	out := make([]FeatureFlag, 0, len(raw))
	for _, item := range raw {
		normalized, err := DecodeOne(item)
		if err != nil {
			return nil, err
		}
		out = append(out, normalized)
	}
	return out, nil
}

func DecodeOne(data []byte) (FeatureFlag, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var item FeatureFlag
	if err := dec.Decode(&item); err != nil {
		return FeatureFlag{}, validationError("invalid feature flag JSON", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return FeatureFlag{}, validationError("invalid feature flag JSON", err)
	}
	if strings.TrimSpace(item.Key) == "" {
		return FeatureFlag{}, validationError("key must not be empty", nil)
	}
	return item, nil
}

func validationError(message string, err error) *apperrors.AppError {
	return apperrors.New(apperrors.CodeValidationFailed, message, err)
}
