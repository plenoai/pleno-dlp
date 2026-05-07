package mysql

import (
	"context"
	"testing"
)

func TestFromData_Positive(t *testing.T) {
	body := "DATABASE_URL=mysql://root:rootp4ss@db.example.com:3306/app"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "rootp4ss" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
}

func TestFromData_MysqlX(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("mysqlx://u:p@h:33060"))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("mysql://db.local:3306/app"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}
