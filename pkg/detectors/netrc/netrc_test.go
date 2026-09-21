//go:build detector_unit

package netrc

import (
	"context"
	"strings"
	"testing"
)

func TestLoginPrefilterPreservesCaseVariants(t *testing.T) {
	keywords := []string{"logİn", "loġin", "llll", "LOGIN"}
	for mask := 0; mask < 1<<len("login"); mask++ {
		keyword := []byte("login")
		for i := range keyword {
			if mask&(1<<i) != 0 {
				keyword[i] -= 'a' - 'A'
			}
		}
		keywords = append(keywords, string(keyword))
	}
	for _, keyword := range keywords {
		data := []byte("machine host " + keyword + " 運用担当 password Qx7-Trout-Ferry-42")
		got, err := (Scanner{}).FromData(context.Background(), false, data)
		if err != nil || (len(got) == 1) != netrcEntryRe().Match(data) {
			t.Fatalf("keyword %q: findings=%d, err=%v", keyword, len(got), err)
		}
	}
}

func BenchmarkRejectKeywordProse(b *testing.B) {
	data := []byte(strings.Repeat("// API documentation: access token, password, secret key.\nconst status = 200; // health check\n", 8192))
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if got, err := (Scanner{}).FromData(context.Background(), false, data); err != nil || len(got) != 0 {
			b.Fatalf("findings=%d, err=%v", len(got), err)
		}
	}
}

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
