// Package postgres provides PostgreSQL storage for authkit.
//
// Applications own connection pool configuration and must call Migrate
// explicitly before constructing a Store. NewStore only validates and wraps the
// supplied pool.
package postgres
