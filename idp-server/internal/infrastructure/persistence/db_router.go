package persistence

import "database/sql"

type dbRouter struct {
	write *sql.DB
	read  *sql.DB
}

func newDBRouter(writeDB, readDB *sql.DB) dbRouter {
	if writeDB == nil {
		writeDB = readDB
	}
	if readDB == nil {
		readDB = writeDB
	}
	return dbRouter{
		write: writeDB,
		read:  readDB,
	}
}

func (r dbRouter) writer() *sql.DB {
	return r.write
}

func (r dbRouter) reader() *sql.DB {
	return r.read
}
