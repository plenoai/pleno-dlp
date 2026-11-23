// Package database maps database connection-string credentials (Postgres,
// MySQL, MongoDB) by connecting with the credential and reading role
// attributes, grants and the database list. Every session is read-only:
// Postgres sessions run with default_transaction_read_only, MySQL sessions
// with SESSION TRANSACTION READ ONLY, and MongoDB only issues the
// connectionStatus/listDatabases commands. No statement writes.
package database

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ConnectTimeout bounds dialing and authentication.
const ConnectTimeout = 10 * time.Second

// QueryTimeout bounds the whole introspection session.
const QueryTimeout = 30 * time.Second

// MaxDatabases caps listed databases.
const MaxDatabases = 1000

// Rows is a minimal result set: column values rendered as strings.
type Rows [][]string

// SQLConn is the subset of a SQL session the mappers use. Production code
// wraps pgx / database/sql; tests supply in-process fakes.
type SQLConn interface {
	Query(ctx context.Context, q string) (Rows, error)
	Close() error
}

// refusedHosts mirrors the detector probes' skip list: documentation and
// loopback hosts are never contacted from scanned material.
var refusedHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "example.com": true, "host.example.com": true}

func checkURI(raw string, schemes ...string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("connection URI does not parse")
	}
	ok := false
	for _, s := range schemes {
		ok = ok || strings.EqualFold(u.Scheme, s)
	}
	if !ok {
		return nil, fmt.Errorf("connection URI scheme must be one of %v", schemes)
	}
	host := u.Hostname()
	if host == "" || u.User == nil {
		return nil, errors.New("connection URI must include host and credentials")
	}
	for _, h := range strings.Split(u.Host, ",") {
		hn := h
		if sh, _, err := net.SplitHostPort(h); err == nil {
			hn = sh
		}
		if refusedHosts[strings.ToLower(strings.Trim(hn, "[]"))] {
			return nil, fmt.Errorf("refusing to connect to %s", hn)
		}
	}
	return u, nil
}

func first(r Rows) string {
	if len(r) == 0 || len(r[0]) == 0 {
		return ""
	}
	return r[0][0]
}

func truthy(s string) bool {
	switch strings.ToLower(s) {
	case "t", "true", "1", "y", "yes", "on":
		return true
	}
	return false
}
