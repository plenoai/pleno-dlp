//go:build detector_unit

package pgpass

import (
	"context"
	"testing"
)

func TestFromData_DataLine(t *testing.T) {
	data := []byte("db.internal.example.com:5432:billing:svc_billing:Tr0ub4dor" + "&3xQ9\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Tr0ub4dor&3xQ9" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["host"] != "db.internal.example.com" {
		t.Fatalf("host = %q", res[0].ExtraData["host"])
	}
}

func TestFromData_WildcardFields(t *testing.T) {
	data := []byte("*:*:*:replicator:R3pl-S3cr3t-9f8e\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "R3pl-S3cr3t-9f8e" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_MultipleLines(t *testing.T) {
	data := []byte(
		"primary.db.example.com:5432:app:app_user:hunter2-Zz8k\n" +
			"replica.db.example.com:5432:app:app_user:hunter2-Zz8k\n",
	)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 2 {
		t.Fatalf("expected 2, got %d", len(res))
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"comment header", "#hostname:port:database:username:password\nlocalhost:5432:database:root:password\n"},
		{"placeholder password", "localhost:5432:mydb:myuser:changeme\n"},
		{"literal password field name", "localhost:5432:mydb:myuser:password\n"},
		{"password equals username", "localhost:5432:mydb:myuser:myuser\n"},
		{"not five fields", "localhost:5432:mydb:secretvalue\n"},
		{"non-numeric port", "localhost:https:mydb:myuser:S0meRea1Pass9\n"},
		{"whitespace in line", "local host:5432:mydb:myuser:S0meRea1Pass9\n"},
		{"prose mentioning colons", "See section 3:4:5 of the runbook for on-call:rotation:policy:details\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}

func TestWantsFullChunk(t *testing.T) {
	if !(Scanner{}.WantsFullChunk()) {
		t.Fatal("expected WantsFullChunk() == true")
	}
}
