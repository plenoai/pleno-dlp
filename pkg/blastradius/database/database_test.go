package database

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

type fakeSQL struct {
	answers map[string]Rows
	seen    []string
	closed  bool
}

func (f *fakeSQL) Query(_ context.Context, q string) (Rows, error) {
	f.seen = append(f.seen, q)
	for k, v := range f.answers {
		if strings.Contains(q, k) {
			return v, nil
		}
	}
	return nil, errors.New("permission denied")
}

func (f *fakeSQL) Close() error { f.closed = true; return nil }

func names(am *detectors.AccessMap, typ string) []string {
	var out []string
	for _, r := range am.Resources {
		if r.Type == typ {
			out = append(out, r.Name)
		}
	}
	return out
}

func assertReadOnly(t *testing.T, qs []string) {
	t.Helper()
	for _, q := range qs {
		u := strings.ToUpper(strings.TrimSpace(q))
		if !strings.HasPrefix(u, "SELECT") && !strings.HasPrefix(u, "SHOW") {
			t.Fatalf("non read-only statement issued: %q", q)
		}
	}
}

func TestPostgres(t *testing.T) {
	f := &fakeSQL{answers: map[string]Rows{
		"rolsuper":        {{"app", "false", "true", "false", "false", "false"}},
		"pg_auth_members": {{"pg_write_all_data"}},
		"pg_database":     {{"app", "app", "true", "true", "true"}, {"other", "postgres", "false", "true", "false"}},
	}}
	am, err := Postgres{Connect: func(context.Context, string) (SQLConn, error) { return f, nil }}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "postgres://app:password@db.internal.acme:5432/app"})
	if err != nil {
		t.Fatal(err)
	}
	if am.Identity.Name != "app" || !am.Privileged || !slices.Equal(am.Permissions, []string{"createrole"}) || !slices.Equal(names(am, "database"), []string{"app", "other"}) || !f.closed {
		t.Fatalf("%+v", am)
	}
	if am.Resources[1].Permissions[0] != "owner" {
		t.Fatalf("owner not recorded: %+v", am.Resources)
	}
	assertReadOnly(t, f.seen)
}

func TestPostgresUnprivileged(t *testing.T) {
	f := &fakeSQL{answers: map[string]Rows{"rolsuper": {{"ro", "f", "f", "f", "f", "f"}}}}
	am, err := Postgres{Connect: func(context.Context, string) (SQLConn, error) { return f, nil }}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "postgresql://ro:password@db.acme.io/x"})
	if err != nil || am.Privileged || len(am.Limitations) < 2 {
		t.Fatalf("%+v %v", am, err)
	}
}

func TestURIGuards(t *testing.T) {
	never := func(context.Context, string) (SQLConn, error) { t.Fatal("must not connect"); return nil, nil }
	for _, uri := range []string{"postgres://u:p@localhost/x", "postgres://u:p@127.0.0.1:5432/x", "http://u:p@db.acme.io/x", "postgres://db.acme.io/x", "postgres://u:p@[::1]:5432/x"} {
		if _, err := (Postgres{Connect: never}).MapAccess(context.Background(), detectors.AccessCredential{Secret: uri}); err == nil {
			t.Fatalf("%q must be refused", uri)
		}
	}
	if _, err := (MongoDB{}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "mongodb://u:p@a.acme.io,localhost:27017/x"}); err == nil {
		t.Fatal("multi-host URI including loopback must be refused")
	}
}

func TestMySQL(t *testing.T) {
	f := &fakeSQL{answers: map[string]Rows{
		"CURRENT_USER()\"":    nil,
		"SELECT CURRENT_USER": {{"app@%"}},
		"SHOW GRANTS":         {{"GRANT USAGE ON *.* TO `app`@`%`"}, {"GRANT SELECT, INSERT ON `shop`.* TO `app`@`%` WITH GRANT OPTION"}},
		"SHOW DATABASES":      {{"information_schema"}, {"shop"}},
	}}
	am, err := MySQL{Connect: func(context.Context, string) (SQLConn, error) { return f, nil }}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "mysql://app:password@db.acme.io/shop"})
	if err != nil {
		t.Fatal(err)
	}
	if am.Identity.Name != "app@%" || !am.Privileged || !slices.Equal(names(am, "grant"), []string{"*.*", "shop.*"}) || !slices.Equal(names(am, "database"), []string{"information_schema", "shop"}) {
		t.Fatalf("%+v", am)
	}
	assertReadOnly(t, f.seen)
}

func TestMySQLUsageOnlyNotPrivileged(t *testing.T) {
	f := &fakeSQL{answers: map[string]Rows{"SELECT CURRENT_USER": {{"ro@%"}}, "SHOW GRANTS": {{"GRANT SELECT ON `a`.* TO `ro`@`%`"}}, "SHOW DATABASES": {{"a"}}}}
	am, err := MySQL{Connect: func(context.Context, string) (SQLConn, error) { return f, nil }}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "mysql://ro:password@db.acme.io/a"})
	if err != nil || am.Privileged {
		t.Fatalf("%+v %v", am, err)
	}
}

type fakeMongo struct{ cmds []string }

func (f *fakeMongo) Run(_ context.Context, cmd bson.D) (map[string]any, error) {
	f.cmds = append(f.cmds, cmd[0].Key)
	switch cmd[0].Key {
	case "connectionStatus":
		return map[string]any{"authInfo": map[string]any{
			"authenticatedUsers":     bson.A{map[string]any{"user": "svc", "db": "admin"}},
			"authenticatedUserRoles": bson.A{map[string]any{"role": "readWriteAnyDatabase", "db": "admin"}},
		}}, nil
	case "listDatabases":
		return map[string]any{"databases": bson.A{map[string]any{"name": "orders"}}}, nil
	}
	return nil, errors.New("unexpected")
}

func (f *fakeMongo) Close() error { return nil }

func TestMongoDB(t *testing.T) {
	f := &fakeMongo{}
	am, err := MongoDB{Connect: func(context.Context, string) (AdminRunner, error) { return f, nil }}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "mongodb+srv://svc:password@cluster0.acme.mongodb.net/"})
	if err != nil {
		t.Fatal(err)
	}
	if am.Identity.ID != "admin.svc" || !am.Privileged || !slices.Equal(names(am, "database"), []string{"orders"}) || !slices.Equal(f.cmds, []string{"connectionStatus", "listDatabases"}) {
		t.Fatalf("%+v %v", am, f.cmds)
	}
}

func TestRedactErr(t *testing.T) {
	err := redactErr(errors.New("dial postgres://u:password@h/x failed: password"), "postgres://u:password@h/x")
	if strings.Contains(err.Error(), "password") || !strings.Contains(err.Error(), "REDACTED") {
		t.Fatal(err)
	}
}

// TestPostgresDialerRequestsReadOnly exercises the real pgx dialer against
// an in-process listener and asserts the startup packet requests a
// read-only session before any credential exchange.
func TestPostgresDialerRequestsReadOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 1024)
		n, _ := c.Read(b)
		got <- b[:n]
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t.Setenv("PGSSLMODE", "disable")
	uri := url.URL{Scheme: "postgres", User: url.UserPassword("u", "password"), Host: ln.Addr().String(), Path: "/db"}
	_, _ = dialPostgres(ctx, uri.String())
	select {
	case b := <-got:
		if !bytes.Contains(b, []byte("default_transaction_read_only\x00on\x00")) {
			t.Fatalf("startup packet lacks read-only param: %q", b)
		}
	case <-ctx.Done():
		t.Fatal("no startup packet")
	}
}
