package azuresqlconn

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestFromData_Positive(t *testing.T) {
	conn := "Server=tcp:my-srv.database.windows.net,1433;Initial Catalog=appdb;Persist Security Info=False;User ID=admin;Password=Sup3rSecret!;MultipleActiveResultSets=False;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(conn))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Sup3rSecret!" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["server"]; got != "my-srv.database.windows.net" {
		t.Fatalf("server: %q", got)
	}
	if got := res[0].ExtraData["user_id"]; got != "admin" {
		t.Fatalf("user: %q", got)
	}
	if got := res[0].ExtraData["database"]; got != "appdb" {
		t.Fatalf("database: %q", got)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("severity: %v", res[0].Severity)
	}
}

func TestFromData_NoHost(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("Server=tcp:localhost;User ID=u;Password=p;"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}

func TestFromData_NoPassword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("Server=tcp:srv.database.windows.net,1433;User ID=u;Authentication=Active Directory Default;"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}

// TestFromData_SuppressFP asserts that template/placeholder and
// interpolation passwords are no longer emitted as Critical secrets after
// the semantic hardening.
func TestFromData_SuppressFP(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{
			name: "documentation placeholder your_password_here",
			in:   "Server=tcp:demo.database.windows.net,1433;Initial Catalog=appdb;User ID=admin;Password=your_password_here;",
		},
		{
			name: "CI env-var interpolation",
			in:   "Server=tcp:srv.database.windows.net,1433;User ID=app;Password=$(DB_PASSWORD);",
		},
		{
			name: "brace template token",
			in:   "Server=tcp:srv.database.windows.net,1433;User ID=app;Password={password};",
		},
		{
			name: "low-entropy dictionary placeholder",
			in:   "Server=tcp:srv.database.windows.net,1433;User ID=app;Password=changeme;",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.in))
			if len(res) != 0 {
				t.Fatalf("expected 0 results, got %d (raw=%q)", len(res), res[0].Raw)
			}
		})
	}
}

// TestFromData_NoCrossStringPairing asserts the tightened vicinity window
// does not pair a host from a passwordless/AAD connection string with a
// Password belonging to an adjacent concatenated connection string many
// segments away.
func TestFromData_NoCrossStringPairing(t *testing.T) {
	// First conn: host present, AAD auth, no password — separated from the
	// second conn's Password by more than the {0,3} vicinity window.
	in := "Server=tcp:aad.database.windows.net,1433;Initial Catalog=db1;Authentication=Active Directory Default;Encrypt=True;TrustServerCertificate=False;Persist Security Info=False;Connection Timeout=30;Pooling=True;Password=RealOtherDbPass;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(in))
	if len(res) != 0 {
		t.Fatalf("expected 0 cross-string pairings, got %d (raw=%q, rawv2=%q)", len(res), res[0].Raw, res[0].RawV2)
	}
}

// TestFromData_StillDetectsReal asserts a genuine high-entropy password
// inside the vicinity window is still detected after hardening.
func TestFromData_StillDetectsReal(t *testing.T) {
	conn := "Server=tcp:prod.database.windows.net,1433;Initial Catalog=appdb;User ID=admin;Password=x9K#mQ7vL2pR;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(conn))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "x9K#mQ7vL2pR" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["server"]; got != "prod.database.windows.net" {
		t.Fatalf("server: %q", got)
	}
}

// TestFromData_DataSourceKeyword asserts the alternate host-bearing keyword
// (Data Source) is still anchored and detected.
func TestFromData_DataSourceKeyword(t *testing.T) {
	conn := "Data Source=alt.database.windows.net,1433;Initial Catalog=db;User ID=u;Password=Tr0ub4dor&3X;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(conn))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}
