// Package migrations embeds the SQL schema migrations so the server binary
// can bring a database up to date on start-up.
package migrations

import "embed"

// FS holds every migration file, applied in lexical order by goose.
//
//go:embed *.sql
var FS embed.FS
