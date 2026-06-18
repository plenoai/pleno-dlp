//go:build detector_unit

package hardcodedpassword

import (
	"context"
	"testing"
)

func TestFromData_TerraformDefault(t *testing.T) {
	data := []byte(`variable "db_password" {
  default = "Aa1234321Bb"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Aa1234321Bb" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_DockerComposeEnv(t *testing.T) {
	data := []byte("DB_PASSWORD=P@ssw0rdXz99\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "P@ssw0rdXz99" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"template var", `password = ${DB_PASSWORD}`},
		{"placeholder changeme", `password = "changeme"`},
		{"placeholder example", `db_password = example`},
		{"too short", `password = abc`},
		{"null", `password = null`},
		{"brace template", `password = {{.Password}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q", len(res), tc.data)
			}
		})
	}
}
