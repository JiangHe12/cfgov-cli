package rule

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/JiangHe12/opskit-core/apperrors"
)

const NacosGroup = "SENTINEL_GROUP"

type Type string

const (
	TypeFlow      Type = "flow"
	TypeDegrade   Type = "degrade"
	TypeSystem    Type = "system"
	TypeAuthority Type = "authority"
	TypeParam     Type = "param"
)

var AllTypes = []Type{TypeFlow, TypeDegrade, TypeSystem, TypeAuthority, TypeParam}

func ParseType(value string) (Type, error) {
	switch Type(strings.TrimSpace(value)) {
	case TypeFlow:
		return TypeFlow, nil
	case TypeDegrade:
		return TypeDegrade, nil
	case TypeSystem:
		return TypeSystem, nil
	case TypeAuthority:
		return TypeAuthority, nil
	case TypeParam:
		return TypeParam, nil
	default:
		return "", apperrors.New(apperrors.CodeUsageError, "unsupported rule type", nil)
	}
}

func DataID(app string, ruleType Type) (string, error) {
	app = strings.TrimSpace(app)
	if err := ValidateApp(app); err != nil {
		return "", err
	}
	if _, err := ParseType(string(ruleType)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-rules", app, ruleType), nil
}

func NacosKey(app string, ruleType Type) (string, error) {
	dataID, err := DataID(app, ruleType)
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

func InferTypeFromPath(path string) (Type, error) {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), filepath.Ext(path))
	for _, ruleType := range AllTypes {
		value := string(ruleType)
		if base == value || base == value+"-rules" || strings.HasSuffix(base, "-"+value+"-rules") || strings.HasSuffix(base, "_"+value) {
			return ruleType, nil
		}
	}
	return "", apperrors.New(apperrors.CodeValidationFailed, "cannot infer rule type from file name", nil)
}
