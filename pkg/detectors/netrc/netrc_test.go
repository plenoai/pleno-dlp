//go:build detector_unit

package netrc

import (
	"context"
	"testing"
)

func TestFromData_LoginThenPassword(t *testing.T) {
	data := []byte("machine imap.example.com login ops@example.com password " + "Qx7-Trout-Ferry-42\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Qx7-Trout-Ferry-42" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["login"] != "ops@example.com" {
		t.Fatalf("login = %q", res[0].ExtraData["login"])
	}
}

func TestFromData_PasswordThenLogin(t *testing.T) {
	data := []byte("machine ftp.example.com password " + "Zn4-Cobalt-Marsh-77 login uploader\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Zn4-Cobalt-Marsh-77" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_MultipleMachines(t *testing.T) {
	data := []byte(
		"machine imap.example.com login example@example.com password " + "aa-bb-cc-dd-11\n" +
			"machine smtp.example.com login example@example.com password " + "ee-ff-gg-hh-22\n",
	)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 2 {
		t.Fatalf("expected 2, got %d", len(res))
	}
}

func TestFromData_DefaultEntry(t *testing.T) {
	data := []byte("default login anonymous password " + "Mn9-Willow-Cavern-13\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"placeholder password", "machine example.com login user password changeme\n"},
		{"literal password field name", "machine example.com login user password password\n"},
		{"password equals login", "machine example.com login sameuser password sameuser\n"},
		{"no password token", "machine example.com login someuser\n"},
		{"prose mentioning password", "Remember to reset your password after the migration.\n"},
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
