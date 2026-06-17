package main

import "embed"

// skillEmbedFS holds the bundled AI skill for `cfgov install <agent> --skills`.
//
//go:embed skills/cfgov-cli
var skillEmbedFS embed.FS
