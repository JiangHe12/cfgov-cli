//go:build windows

package cmd

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type testTokenOwner struct {
	owner *windows.SID
}

func configureTestProcessSecurity() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&token,
	); err != nil {
		return err
	}
	defer func() { _ = token.Close() }()

	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	owner := testTokenOwner{owner: user.User.Sid}
	return windows.SetTokenInformation(
		token,
		windows.TokenOwner,
		(*byte)(unsafe.Pointer(&owner)),
		uint32(unsafe.Sizeof(owner)),
	)
}

func secureTestHomeRoot(path string) error {
	if err := setMutationSpoolACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		return err
	}
	return verifyMutationSpoolDirectory(path)
}
