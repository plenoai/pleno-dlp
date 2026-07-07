//go:build detector_unit

package jslogincallsecret

import (
	"context"
	"testing"
)

func TestFromData_LoginCall(t *testing.T) {
	data := []byte(`let jsforce = require('jsforce');

function sfQuery(queryString, success, error){
    let conn = new jsforce.Connection();
    conn.login('svcacct@corp.example.org', 'Tr0ub4dor&9xQ', function(err, res) {
        if (err) { error(err); }
    });
}
`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "Tr0ub4dor&9xQ" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["identity"] != "svcacct@corp.example.org" {
		t.Fatalf("got identity %q", res[0].ExtraData["identity"])
	}
}

func TestFromData_AuthenticateCall(t *testing.T) {
	data := []byte(`client.authenticate("ops@internal.dev", "Zq7$mN2pLxR9")`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "Zq7$mN2pLxR9" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"no email-shaped first arg", `conn.login('svcacct', 'Tr0ub4dor&9xQ')`},
		{"placeholder secret", `conn.login('svcacct@corp.example.org', 'password')`},
		{"too short secret", `conn.login('svcacct@corp.example.org', 'ab')`},
		{"bare connect() with no credential pair", `socket.connect('wss://events.internal')`},
		{"login used as a function definition, not a call", `function login(user, pass) { return pass; }`},
		{"single positional arg only", `conn.login('svcacct@corp.example.org')`},
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

func TestFromData_Dedup(t *testing.T) {
	data := []byte(`
conn.login('svcacct@corp.example.org', 'Tr0ub4dor&9xQ', cb);
conn.login('svcacct@corp.example.org', 'Tr0ub4dor&9xQ', cb);
`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d: %+v", len(res), res)
	}
}
