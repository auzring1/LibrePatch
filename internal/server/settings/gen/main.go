// Command gen writes docs/SETTINGS.md from the settings registry, so the documentation of every setting is the registry
// itself and cannot drift from it.
//
//	go run ./internal/server/settings/gen > docs/SETTINGS.md
package main

import (
	"fmt"

	"github.com/auzring1/librepatch/internal/server/settings"
)

func main() { fmt.Print(settings.Markdown()) }
