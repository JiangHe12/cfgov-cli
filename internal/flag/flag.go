package flag

import (
	"fmt"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

// NacosGroup is intentionally separate from rule.NacosGroup: feature flags are
// another typed policy family, not Sentinel rule config.
const NacosGroup = "FEATURE_FLAG_GROUP"

func DataID(app string) (string, error) {
	app = strings.TrimSpace(app)
	if err := ValidateApp(app); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-flags", app), nil
}

func NacosKey(app string) (string, error) {
	dataID, err := DataID(app)
	if err != nil {
		return "", err
	}
	return NacosGroup + "/" + dataID, nil
}

func ValidateApp(app string) error {
	if app == "" || app == "." || app == ".." {
		return apperrors.New(apperrors.CodeUsageError, "--app is required", nil)
	}
	if strings.ContainsAny(app, "\x00\r\n\t/\\") {
		return apperrors.New(apperrors.CodeValidationFailed, "app contains invalid characters", nil)
	}
	return nil
}

func Key(item FeatureFlag) string {
	return item.Key
}
