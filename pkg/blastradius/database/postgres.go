package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Postgres maps a postgres:// URI credential.
type Postgres struct {
	// Connect overrides the pgx dialer (tests).
	Connect func(ctx context.Context, uri string) (SQLConn, error)
}

type pgConn struct{ c *pgx.Conn }

func (p pgConn) Query(ctx context.Context, q string) (Rows, error) {
	rows, err := p.c.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out Rows
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return out, err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			if v != nil {
				row[i] = fmt.Sprint(v)
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (p pgConn) Close() error { return p.c.Close(context.Background()) }

func dialPostgres(ctx context.Context, uri string) (SQLConn, error) {
	cfg, err := pgx.ParseConfig(uri)
	if err != nil {
		return nil, fmt.Errorf("parse URI: %w", redactErr(err, uri))
	}
	cfg.ConnectTimeout = ConnectTimeout
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["application_name"] = "pleno-dlp-blast-radius"
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, redactErr(err, uri)
	}
	return pgConn{c}, nil
}

const pgRoleQuery = `SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user`
const pgMemberQuery = `SELECT r.rolname FROM pg_roles r JOIN pg_auth_members m ON m.roleid = r.oid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = current_user ORDER BY 1`
const pgDBQuery = `SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba), has_database_privilege(d.datname, 'CREATE'), has_database_privilege(d.datname, 'CONNECT'), has_database_privilege(d.datname, 'TEMP') FROM pg_database d WHERE NOT d.datistemplate ORDER BY 1 LIMIT 1001`

// MapAccess implements detectors.AccessMapper. cred.Secret is the URI.
func (m Postgres) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	if _, err := checkURI(cred.Secret, "postgres", "postgresql"); err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	connect := m.Connect
	if connect == nil {
		connect = dialPostgres
	}
	c, err := connect(ctx, cred.Secret)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	defer c.Close()
	role, err := c.Query(ctx, pgRoleQuery)
	if err != nil || len(role) == 0 || len(role[0]) < 6 {
		return nil, fmt.Errorf("postgres: role attributes: %v", err)
	}
	r := role[0]
	am := detectors.NewAccessMap("postgres")
	am.Identity = detectors.AccessIdentity{ID: r[0], Name: r[0], Type: "role"}
	for i, attr := range []string{"superuser", "createrole", "createdb", "replication", "bypassrls"} {
		if truthy(r[i+1]) {
			am.Permissions = append(am.Permissions, attr)
			if attr == "superuser" || attr == "createrole" || attr == "replication" || attr == "bypassrls" {
				am.Privileged = true
			}
		}
	}
	if mem, err := c.Query(ctx, pgMemberQuery); err != nil {
		am.Limitations = append(am.Limitations, "role memberships: "+err.Error())
	} else {
		for _, row := range mem {
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "role", Name: row[0], Permissions: []string{"member"}})
			if row[0] == "pg_write_all_data" || row[0] == "pg_execute_server_program" || row[0] == "pg_read_server_files" || row[0] == "pg_write_server_files" || row[0] == "rds_superuser" || row[0] == "azure_pg_admin" || row[0] == "cloudsqlsuperuser" {
				am.Privileged = true
			}
		}
	}
	dbs, err := c.Query(ctx, pgDBQuery)
	if err != nil {
		am.Limitations = append(am.Limitations, "databases: "+err.Error())
	}
	if len(dbs) > MaxDatabases {
		dbs = dbs[:MaxDatabases]
		am.Limitations = append(am.Limitations, fmt.Sprintf("database listing capped at %d", MaxDatabases))
	}
	for _, row := range dbs {
		if len(row) < 5 {
			continue
		}
		res := detectors.AccessResource{Type: "database", Name: row[0]}
		if row[1] == r[0] {
			res.Permissions = append(res.Permissions, "owner")
		}
		for i, p := range []string{"create", "connect", "temp"} {
			if truthy(row[i+2]) {
				res.Permissions = append(res.Permissions, p)
			}
		}
		am.Resources = append(am.Resources, res)
	}
	am.Limitations = append(am.Limitations, "table-level grants are not enumerated")
	return am, nil
}

// redactErr strips the password from driver errors that echo the URI.
func redactErr(err error, uri string) error {
	msg := err.Error()
	if i := strings.Index(uri, "://"); i >= 0 {
		if at := strings.LastIndex(uri, "@"); at > i {
			if c := strings.Index(uri[i+3:at], ":"); c >= 0 {
				if pw := uri[i+3+c+1 : at]; pw != "" {
					msg = strings.ReplaceAll(msg, pw, "REDACTED")
				}
			}
		}
	}
	return fmt.Errorf("%s", msg)
}
