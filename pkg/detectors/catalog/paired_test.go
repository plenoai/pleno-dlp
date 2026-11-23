package catalog

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func verifiedRaw(t *testing.T, res []detectors.Result, raw string) detectors.Result {
	t.Helper()
	for _, r := range res {
		if string(r.Raw) == raw {
			return r
		}
	}
	t.Fatalf("no result for %q in %+v", raw, res)
	return detectors.Result{}
}

// Finicity pairs App-Key and partner ID from the window (issue #956).
func TestFinicityPairing(t *testing.T) {
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = io.WriteString(w, `{"token":"t"}`)
	})
	key := "0123456789abcdef0123456789abcdef"
	sec := "a1b2c3d4e5f6g7h8i9j0"
	data := []byte("FINICITY_APP_KEY=" + key + "\nFINICITY_PARTNER_ID=2445582695152\nFINICITY_SECRET=" + sec + "\n")
	res, err := hostDetector(t, detectors.Finicity).FromData(context.Background(), true, data)
	if err != nil {
		t.Fatal(err)
	}
	if r := verifiedRaw(t, res, sec); !r.Verified {
		t.Fatalf("secret not verified: %+v", r)
	}
	req, body := cp.get()
	var got map[string]string
	_ = json.Unmarshal([]byte(body), &got)
	if req.Header.Get("Finicity-App-Key") != key || got["partnerId"] != "2445582695152" || got["partnerSecret"] != sec || len(got) != 2 {
		t.Fatalf("request %v %q", req.Header, body)
	}
	if r := verifiedRaw(t, res, key); !r.Verified {
		t.Fatalf("app key not verified: %+v", r)
	}

	// Without the partner ID the verdict is unknown, never invalid.
	res, _ = hostDetector(t, detectors.Finicity).FromData(context.Background(), true,
		[]byte("FINICITY_APP_KEY="+key+"\nFINICITY_SECRET="+sec+"\n"))
	r := verifiedRaw(t, res, sec)
	if r.Verified || r.VerificationErr == nil {
		t.Fatalf("missing partner must be indeterminate: %+v", r)
	}
}

func TestKuCoinSignature(t *testing.T) {
	ts := fixedNow(t)
	key := "5f2c8a0b9d1e3f4a5b6c7d8e"
	sec := "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	pass := "hunter2pass"
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = io.WriteString(w, `{"code":"200000","data":[]}`)
	})
	data := []byte("KUCOIN_API_KEY=" + key + "\nKUCOIN_API_SECRET=" + sec + "\nKUCOIN_API_PASSPHRASE=" + pass + "\n")
	res, err := hostDetector(t, detectors.KuCoin).FromData(context.Background(), true, data)
	if err != nil {
		t.Fatal(err)
	}
	if !verifiedRaw(t, res, sec).Verified || !verifiedRaw(t, res, key).Verified {
		t.Fatalf("kucoin pair not verified: %+v", res)
	}
	req, _ := cp.get()
	mac := func(k, m string) string {
		h := hmac.New(sha256.New, []byte(k))
		h.Write([]byte(m))
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	ms := strconv.FormatInt(ts.UnixMilli(), 10)
	if req.Host != "api.kucoin.com" || req.Header.Get("KC-API-KEY") != key || req.Header.Get("KC-API-TIMESTAMP") != ms ||
		req.Header.Get("KC-API-SIGN") != mac(sec, ms+"GET/api/v1/accounts") ||
		req.Header.Get("KC-API-PASSPHRASE") != mac(sec, pass) || req.Header.Get("KC-API-KEY-VERSION") != "2" {
		t.Fatalf("kucoin headers %v", req.Header)
	}

	// A wrong passphrase does not reject the secret; a bad signature does.
	fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"code":"400004","msg":"Invalid KC-API-PASSPHRASE"}`)
	})
	if ok, err := checks["betterleaks.kucoin-secret-key"].verify(context.Background(), detectors.KuCoin, "k", sec, data); ok || err == nil {
		t.Fatalf("bad passphrase: (%v, %v), want indeterminate", ok, err)
	}
	fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"code":"400005","msg":"Invalid KC-API-SIGN"}`)
	})
	if ok, err := checks["betterleaks.kucoin-secret-key"].verify(context.Background(), detectors.KuCoin, "k", sec, data); ok || err != nil {
		t.Fatalf("bad signature: (%v, %v), want invalid", ok, err)
	}
	if ok, err := checks["betterleaks.kucoin-access-token"].verify(context.Background(), detectors.KuCoin, "k", key, data); ok || err == nil {
		t.Fatalf("bad signature must not reject the API key: (%v, %v)", ok, err)
	}
}

func TestFreemiusSignature(t *testing.T) {
	ts := fixedNow(t)
	sec := "sk_" + strings.Repeat("Ab1", 9) + "Xy"
	pub := "pk_" + strings.Repeat("Cd2", 9) + "Zw"
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = io.WriteString(w, `{"id":"1234"}`)
	})
	data := []byte("fs_dynamic_init( array(\n 'id' => '1234',\n 'public_key' => '" + pub + "',\n 'secret_key' => '" + sec + "',\n) );")
	ok, err := checks["betterleaks.freemius-secret-key"].verify(context.Background(), detectors.Freemius, "f", sec, data)
	if !ok || err != nil {
		t.Fatalf("freemius: (%v, %v)", ok, err)
	}
	req, _ := cp.get()
	date := ts.UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")
	h := hmac.New(sha256.New, []byte(sec))
	h.Write([]byte("GET\n\n\n" + date + "\n/v1/plugins/1234.json"))
	sig := strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h.Sum(nil))))), "=")
	if req.Host != "api.freemius.com" || req.URL.Path != "/v1/plugins/1234.json" || req.Header.Get("Date") != date ||
		req.Header.Get("Authorization") != "FS 1234:"+pub+":"+sig {
		t.Fatalf("freemius request %s %v", req.URL, req.Header)
	}
	if ok, err := checks["betterleaks.freemius-secret-key"].verify(context.Background(), detectors.Freemius, "f", sec, []byte("'secret_key' => '"+sec+"'")); ok || err == nil {
		t.Fatalf("missing id/public key: (%v, %v), want indeterminate", ok, err)
	}
}

// SettleMint tokens go only to a settlemint.com URL found in the text.
func TestSettleMintDeploymentURL(t *testing.T) {
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) { _, _ = io.WriteString(w, `{}`) })
	tok := "sm_aat_Ab12Cd34Ef56Gh78"
	res, err := hostDetector(t, detectors.SettleMint).FromData(context.Background(), true,
		[]byte("SETTLEMINT_URL=https://my-node-1a2b.gke-europe.settlemint.com\nSETTLEMINT_TOKEN="+tok+"\n"))
	if err != nil || !verifiedRaw(t, res, tok).Verified {
		t.Fatalf("settlemint: %+v %v", res, err)
	}
	if req, _ := cp.get(); req.Host != "my-node-1a2b.gke-europe.settlemint.com" || req.Header.Get("x-auth-token") != tok {
		t.Fatalf("settlemint request %v", req)
	}
	for _, u := range []string{"https://settlemint.com.attacker.example", "https://attacker.example/x.settlemint.com", "http://a.settlemint.com"} {
		if ok, err := checks["betterleaks.settlemint-application-access-token"].http.do(context.Background(), "sm", vars{"secret": tok, "url": u}); ok || err == nil {
			t.Errorf("%s: (%v, %v), want refusal", u, ok, err)
		}
	}
	if ok, err := checks["betterleaks.settlemint-application-access-token"].verify(context.Background(), detectors.SettleMint, "sm", tok, []byte(tok)); ok || err == nil {
		t.Fatalf("no deployment URL: (%v, %v), want indeterminate", ok, err)
	}
}

func TestLinkedInClientProbe(t *testing.T) {
	cid, sec := "86abcdefgh1234", "Zx9Yw8Vu7Ts6Rq5P"
	data := []byte("LINKEDIN_CLIENT_ID=" + cid + "\nLINKEDIN_CLIENT_SECRET=" + sec + "\n")
	fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"Client authentication failed"}`)
	})
	if ok, err := checks["betterleaks.linkedin-client-secret"].verify(context.Background(), detectors.LinkedIn, "li", sec, data); ok || err != nil {
		t.Fatalf("invalid_client: (%v, %v), want invalid", ok, err)
	}
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"invalid_request","error_description":"Unable to retrieve access token: authorization code not found"}`)
	})
	if ok, err := checks["betterleaks.linkedin-client-secret"].verify(context.Background(), detectors.LinkedIn, "li", sec, data); !ok || err != nil {
		t.Fatalf("accepted client: (%v, %v)", ok, err)
	}
	if _, body := cp.get(); !strings.Contains(body, "client_id="+cid) {
		t.Fatalf("body %q", body)
	}
}
