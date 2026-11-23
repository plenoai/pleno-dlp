package database

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-sql-driver/mysql"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// MySQL maps a mysql:// URI credential.
type MySQL struct {
	Connect func(ctx context.Context, uri string) (SQLConn, error)
}

type sqlConn struct {
	c  *sql.Conn
	db *sql.DB
}

func (s sqlConn) Query(ctx context.Context, q string) (Rows, error) {
	rows, err := s.c.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out Rows
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return out, err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s sqlConn) Close() error { _ = s.c.Close(); return s.db.Close() }

func dialMySQL(ctx context.Context, uri string) (SQLConn, error) {
	u, err := checkURI(uri, "mysql")
	if err != nil {
		return nil, err
	}
	cfg := mysql.NewConfig()
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.Net = "tcp"
	cfg.Addr = u.Host
	if u.Port() == "" {
		cfg.Addr = u.Host + ":3306"
	}
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	cfg.Timeout = ConnectTimeout
	cfg.ReadTimeout = QueryTimeout
	cfg.AllowNativePasswords = true
	if q := u.Query().Get("tls"); q != "" {
		cfg.TLSConfig = q
	} else {
		cfg.TLSConfig = "preferred"
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, redactErr(err, uri)
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	c, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, redactErr(err, uri)
	}
	if _, err := c.ExecContext(ctx, "SET SESSION TRANSACTION READ ONLY"); err != nil {
		_ = c.Close()
		_ = db.Close()
		return nil, redactErr(err, uri)
	}
	return sqlConn{c: c, db: db}, nil
}

var grantRe = regexp.MustCompile(`(?i)^GRANT (.+?) ON (\S+) TO `)

var mysqlPrivileged = map[string]bool{
	"ALL PRIVILEGES": true, "SUPER": true, "GRANT OPTION": true, "CREATE USER": true, "FILE": true,
	"SHUTDOWN": true, "PROCESS": true, "RELOAD": true, "SYSTEM_USER": true, "SYSTEM_VARIABLES_ADMIN": true,
}

// MapAccess implements detectors.AccessMapper. cred.Secret is the URI.
func (m MySQL) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	if _, err := checkURI(cred.Secret, "mysql"); err != nil {
		return nil, fmt.Errorf("mysql: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	connect := m.Connect
	if connect == nil {
		connect = dialMySQL
	}
	c, err := connect(ctx, cred.Secret)
	if err != nil {
		return nil, fmt.Errorf("mysql: connect: %w", err)
	}
	defer c.Close()
	user, err := c.Query(ctx, "SELECT CURRENT_USER()")
	if err != nil || first(user) == "" {
		return nil, fmt.Errorf("mysql: current user: %v", err)
	}
	am := detectors.NewAccessMap("mysql")
	am.Identity = detectors.AccessIdentity{ID: first(user), Name: first(user), Type: "user"}
	grants, err := c.Query(ctx, "SHOW GRANTS FOR CURRENT_USER()")
	if err != nil {
		am.Limitations = append(am.Limitations, "grants: "+err.Error())
	}
	for _, row := range grants {
		g := grantRe.FindStringSubmatch(first(Rows{row}))
		if g == nil {
			continue
		}
		var privs []string
		for _, p := range strings.Split(g[1], ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			privs = append(privs, p)
			if mysqlPrivileged[p] && (g[2] == "*.*" || p == "GRANT OPTION" || p == "ALL PRIVILEGES") {
				am.Privileged = true
			}
		}
		if strings.Contains(strings.ToUpper(row[0]), "WITH GRANT OPTION") {
			privs = append(privs, "GRANT OPTION")
			am.Privileged = true
		}
		if g[2] == "*.*" {
			am.Permissions = append(am.Permissions, privs...)
		}
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "grant", Name: strings.ReplaceAll(g[2], "`", ""), Permissions: privs})
	}
	dbs, err := c.Query(ctx, "SHOW DATABASES")
	if err != nil {
		am.Limitations = append(am.Limitations, "databases: "+err.Error())
	}
	if len(dbs) > MaxDatabases {
		dbs = dbs[:MaxDatabases]
		am.Limitations = append(am.Limitations, fmt.Sprintf("database listing capped at %d", MaxDatabases))
	}
	for _, row := range dbs {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "database", Name: first(Rows{row})})
	}
	return am, nil
}
