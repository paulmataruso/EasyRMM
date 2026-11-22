//go:build integration

package database

import "github.com/jackc/pgx/v5"

// LeaderConn is the connection that holds l's lock, for tests.
func LeaderConn(l *Leader) *pgx.Conn { return l.conn }
