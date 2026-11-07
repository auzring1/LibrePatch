// Package db embeds the SQL migrations so the server binary is self-contained.
package db

import "embed"

// Migrations holds goose migrations (forward-only in production).
//
//go:embed migrations/*.sql
var Migrations embed.FS
