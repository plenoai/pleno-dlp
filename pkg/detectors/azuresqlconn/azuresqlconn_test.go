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
