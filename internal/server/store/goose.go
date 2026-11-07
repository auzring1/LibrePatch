package store

import (
	"io/fs"

	"github.com/pressly/goose/v3/lock"

	"github.com/auzring1/librepatch/db"
)

func migrationsFS() fs.FS {
	sub, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

func mustLocker() lock.SessionLocker {
	l, err := lock.NewPostgresSessionLocker()
	if err != nil {
		panic(err)
	}
	return l
}
