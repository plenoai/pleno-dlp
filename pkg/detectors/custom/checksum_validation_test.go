package custom

import (
	"context"
	"crypto/tls"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ghStyleToken(body string) string {
	return "acme_" + body + fitWidth(base62(crc32.ChecksumIEEE([]byte(body))), 6)
}

func TestChecksumCRC32Base62(t *testing.T) {
	d, err := Compile(Rule{
		Name: "acme", Keywords: []string{"acme_"},
		Regex:    `acme_(?P<body>[A-Za-z0-9]{30})(?P<crc>[A-Za-z0-9]{6})`,
		Checksum: &Checksum{Algorithm: "crc32_base62", BodyGroup: "body", ChecksumGroup: "crc", Length: 6},
	})
	if err != nil {
		t.Fatal(err)
	}
	good := ghStyleToken("abcdefghijklmnopqrstuvwxyz0123")
	bad := good[:len(good)-1] + "Z"
	if bad == good {
		bad = good[:len(good)-1] + "Y"
	}
	res, _ := d.FromData(context.Background(), false, []byte(good+" "+bad))
	if len(res) != 1 || string(res[0].Raw) != good || res[0].ExtraData["checksum"] != "valid" {
		t.Fatalf("want only valid token, got %+v", res)
	}
}

func TestChecksumLuhnIBAN(t *testing.T) {
	if !luhnValid("4111 1111 1111 1111") || luhnValid("4111111111111112") {
		t.Fatal("luhn")
	}
	if !ibanValid("GB82 WEST 1234 5698 7654 32") || ibanValid("GB82WEST12345698765433") {
		t.Fatal("iban")
	}
	d, err := Compile(Rule{Name: "card", Keywords: []string{"card"}, Regex: `card=(?P<pan>[0-9]{16})`,
		Checksum: &Checksum{Algorithm: "luhn", BodyGroup: "pan"}})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := d.FromData(context.Background(), false, []byte("card=4111111111111111 card=4111111111111112"))
	if len(res) != 1 {
		t.Fatalf("want 1 luhn-valid result, got %d", len(res))
	}
}

func TestChecksumCompileErrors(t *testing.T) {
	for name, c := range map[string]*Checksum{
		"unknown algo":  {Algorithm: "md5"},
		"missing group": {Algorithm: "crc32_hex", ChecksumGroup: "nope", Length: 8},
		"bad length":    {Algorithm: "crc32_hex", ChecksumGroup: "crc", Length: 0},
		"no sum group":  {Algorithm: "crc32_dec", Length: 4},
	} {
		if _, err := Compile(Rule{Name: "r", Keywords: []string{"x"}, Regex: `x(?P<crc>[0-9a-f]{8})`, Checksum: c}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestValidationCompileSSRFGuards(t *testing.T) {
	re := `tok_(?P<t>[a-z]{8})`
	cases := map[string]Validation{
		"http scheme":        {URL: "http://api.example/v?k={{ .Secret }}"},
		"secret in host":     {URL: "https://{{ .Secret }}.example/"},
		"secret in port":     {URL: "https://api.example:{{ .Secret }}/"},
		"secret in userinfo": {URL: "https://{{ .Secret }}@api.example/"},
		"unknown group":      {URL: "https://api.example/{{ .Group.nope }}"},
		"raw template":       {URL: "https://api.example/{{ printf \"x\" }}"},
		"host header":        {URL: "https://api.example/", Headers: map[string]string{"Host": "evil"}},
		"templated header":   {URL: "https://api.example/", Headers: map[string]string{"X-{{ .Secret }}": "v"}},
		"bad method":         {URL: "https://api.example/", Method: "DELETE"},
	}
	for name, v := range cases {
		v := v
		if _, err := Compile(Rule{Name: "r", Keywords: []string{"tok_"}, Regex: re, Validation: &v}); err == nil {
			t.Errorf("%s: expected compile error", name)
		}
	}
	v := Validation{URL: "https://api.example/"}
	if _, err := Compile(Rule{Name: "r", Keywords: []string{"tok_"}, Regex: re, Validation: &v, VerifyURL: "https://x.example"}); err == nil {
		t.Error("validation + verify_url must be rejected")
	}
}

func TestValidationRefusesPrivateAddressByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request must not reach a loopback server")
	}))
	defer srv.Close()
	d, err := Compile(Rule{Name: "r", Keywords: []string{"tok_"}, Regex: `tok_[a-z]{8}`,
		Validation: &Validation{URL: srv.URL + "/v?k={{ .Secret }}"}})
	if err != nil {
		t.Fatal(err)
	}
	trustTestServer(d, srv)
	res, _ := d.FromData(context.Background(), true, []byte("tok_abcdefgh"))
	if len(res) != 1 || res[0].Verified || res[0].VerificationErr == nil ||
		!strings.Contains(res[0].VerificationErr.Error(), "non-public") {
		t.Fatalf("want non-public refusal, got %+v", res)
	}
}

func TestValidationTemplatedRequest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Query().Get("k") != "tok_a&b=cdef" ||
			r.Header.Get("Authorization") != "Bearer a&b=cdef" || string(b) != `{"t":"a&b=cdef"}` {
			t.Errorf("unexpected request %s %s %q %q", r.Method, r.URL, r.Header.Get("Authorization"), b)
		}
		if strings.Contains(r.URL.RawQuery, "tok_a&b") {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer srv.Close()
	d, err := Compile(Rule{Name: "r", Keywords: []string{"tok_"}, Regex: `tok_(?P<t>[a-z&=]{8})`,
		Validation: &Validation{
			Method: "POST", URL: srv.URL + "/v?k={{ .Secret }}",
			Headers:             map[string]string{"Authorization": "Bearer {{.Group.t}}"},
			Body:                `{"t":"{{ .Group.t }}"}`,
			SuccessBodyContains: `"active":true`,
			AllowPrivateNetwork: true,
		}})
	if err != nil {
		t.Fatal(err)
	}
	trustTestServer(d, srv)
	res, _ := d.FromData(context.Background(), true, []byte("tok_a&b=cdef"))
	if len(res) != 1 || !res[0].Verified || res[0].VerificationErr != nil {
		t.Fatalf("want verified, got %+v", res)
	}
}

func TestValidationNoRedirectAndFailureStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		if r.URL.Path == "/ok" {
			t.Error("redirect must not be followed")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	for path, wantErr := range map[string]bool{"/redir": true, "/deny": false} {
		d, err := Compile(Rule{Name: "r", Keywords: []string{"tok_"}, Regex: `tok_[a-z]{8}`,
			Validation: &Validation{URL: srv.URL + path, AllowPrivateNetwork: true}})
		if err != nil {
			t.Fatal(err)
		}
		trustTestServer(d, srv)
		res, _ := d.FromData(context.Background(), true, []byte("tok_abcdefgh"))
		if len(res) != 1 || res[0].Verified || (res[0].VerificationErr != nil) != wantErr {
			t.Errorf("%s: got %+v", path, res)
		}
	}
}

func TestPublicIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "224.0.0.1"} {
		if publicIP(net.ParseIP(s)) {
			t.Errorf("%s must be non-public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2606:4700::1111"} {
		if !publicIP(net.ParseIP(s)) {
			t.Errorf("%s must be public", s)
		}
	}
}

func trustTestServer(d *Detector, srv *httptest.Server) {
	tr := d.valid.client.Transport.(*http.Transport)
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
}
