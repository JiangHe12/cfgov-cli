package cfgov

import (
	"strings"

	"github.com/JiangHe12/opskit-core/apperrors"
)

type NacosKey struct {
	Group  string
	DataID string
}

func ParseNacosKey(key string) (NacosKey, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return NacosKey{}, apperrors.New(apperrors.CodeUsageError, "--key is required", nil)
	}
	if strings.ContainsAny(key, "\x00\r\n") {
		return NacosKey{}, apperrors.New(apperrors.CodeValidationFailed, "config key contains invalid control characters", nil)
	}
	group, dataID, ok := strings.Cut(key, "/")
	if !ok {
		if isPathTraversalComponent(key) {
			return NacosKey{}, apperrors.New(apperrors.CodeValidationFailed, "config dataId cannot be . or ..", nil)
		}
		return NacosKey{Group: DefaultGroup, DataID: key}, nil
	}
	group = strings.TrimSpace(group)
	dataID = strings.TrimSpace(dataID)
	if group == "" || dataID == "" {
		return NacosKey{}, apperrors.New(apperrors.CodeUsageError, "key must be dataId or group/dataId", nil)
	}
	if isPathTraversalComponent(group) || isPathTraversalComponent(dataID) {
		return NacosKey{}, apperrors.New(apperrors.CodeValidationFailed, "config group and dataId cannot be . or ..", nil)
	}
	return NacosKey{Group: group, DataID: dataID}, nil
}

func isPathTraversalComponent(value string) bool {
	return value == "." || value == ".."
}

func FormatNacosKey(group, dataID string) string {
	if group == "" || group == DefaultGroup {
		return dataID
	}
	return group + "/" + dataID
}
