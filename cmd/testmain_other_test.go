//go:build !windows

package cmd

func configureTestProcessSecurity() error {
	return nil
}

func secureTestHomeRoot(string) error {
	return nil
}
