//go:build detector_unit

package esmtprc

import (
	"context"
	"testing"
)

func TestFromData_QuotedValue(t *testing.T) {
	data := []byte("identity \"example@gmail.com\"\n" +
		"hostname smtp.gmail.com:587\n" +
		"username \"example@gmail.com\"\n" +
		"password \"R3alSMTPPassZz8k\"\n" +
		"starttls required\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "R3alSMTPPassZz8k" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_BareValue(t *testing.T) {
	data := []byte("password R3alSMTPPassZz8k\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "R3alSMTPPassZz8k" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		// leaky-repo's own .esmtprc fixture: the ground-truth value IS
		// the literal placeholder "password" — see package doc comment
		// for why this stays suppressed (same rationale as pgpass's
		// db/.pgpass fixture).
		{"literal password placeholder, quoted", `password "password"`},
		{"literal password placeholder, bare", `password password`},
		{"too short", `password ab`},
		{"trailing text on line breaks grammar", `password R3alPassZz8k extra-token`},
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
