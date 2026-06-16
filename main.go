package main

import "github.com/JiangHe12/cfgov-cli/cmd"

var (
	version = "dev"
	commit  = "unknown"
	built   = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, built)
	cmd.Execute()
}
