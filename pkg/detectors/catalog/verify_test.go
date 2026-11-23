package catalog

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // test mirrors the provider scheme
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// capture records the last request a fake provider received.
type capture struct {
	mu   sync.Mutex
	req  *http.Request
	body string
}

func (c *capture) get() (*http.Request, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.req, c.body
}

// fakeProvider routes every verification request (any host) to handler,
// over TLS, and restores the real client afterwards.
func fakeProvider(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body string)) *capture {
	t.Helper()
	c := &capture{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.req, c.body = r.Clone(context.Background()), string(b)
		c.mu.Unlock()
		handler(w, r, string(b))
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	tr := client.Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // test server
	old := verifyClient
	verifyClient = &http.Client{Transport: tr, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { verifyClient = old })
	return c
}

func respond(rule tokenverify.Rule) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, _ *http.Request, _ string) {
		status := rule.Status
		if status == 0 {
			status = http.StatusBadRequest
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"probe":true,`+rule.BodyContains+`}`)
	}
}

var urlVar = detectors.MustCompile(`^\{(\w+)\}`)

// sampleVars gives every partner a value; a partner that forms the URL
// host gets a host inside the check's allowlist.
func sampleVars(c *check, secret string) vars {
	v := vars{"secret": secret}
	for n := range c.partners {
		v[strings.TrimPrefix(n, "?")] = "partnervalue1234"
	}
	if c.http != nil && len(c.http.Hosts) > 0 {
		host := "tenant." + c.http.Hosts[0]
		if strings.Count(c.http.Hosts[0], ".") >= 2 {
			host = c.http.Hosts[0]
		}
		if m := urlVar.FindStringSubmatch(c.http.URL); m != nil {
			v[m[1]] = "https://" + host
		}
		if m := detectors.MustCompile(`https://\{(\w+)\}`).FindStringSubmatch(c.http.URL); m != nil {
			v[m[1]] = host
		}
	}
	return v
}

func secretSeen(r *http.Request, body, secret string) bool {
	if strings.Contains(r.URL.String(), secret) || strings.Contains(r.URL.String(), url.QueryEscape(secret)) ||
		strings.Contains(body, secret) || strings.Contains(body, url.QueryEscape(secret)) {
		return true
	}
	for _, vals := range r.Header {
		for _, val := range vals {
			if strings.Contains(val, secret) {
				return true
			}
		}
	}
	if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")); err == nil && string(b) == secret {
		return true
	}
	if _, p, ok := r.BasicAuth(); ok && p == secret {
		return true
	}
	if u, pw, ok := r.BasicAuth(); ok && (u == secret || u+":"+pw == secret || u+pw == secret) {
		return true
	}
	return false
}

// Every declarative check reaches its provider with the secret, accepts
// its own valid response, and rejects its own invalid response.
func TestHTTPChecksClassifyBothWays(t *testing.T) {
	const secret = "Sekr3tVal_ue9876"
	for id, c := range checks {
		if c.http == nil {
			continue
		}
		t.Run(id, func(t *testing.T) {
			if c.assurance == detectors.AssuranceUnknown {
				t.Fatal("check declares no assurance")
			}
			valid := c.http.Valid[0]
			cp := fakeProvider(t, respond(valid))
			ok, err := c.http.do(context.Background(), id, sampleVars(c, secret))
			if !ok || err != nil {
				t.Fatalf("valid response: got (%v, %v)", ok, err)
			}
			r, body := cp.get()
			if !secretSeen(r, body, secret) {
				t.Fatalf("request did not carry the secret: %s %v %q", r.URL, r.Header, body)
			}
			invalid := tokenverify.Rule{Status: http.StatusUnauthorized}
			if len(c.http.Invalid) > 0 {
				invalid = c.http.Invalid[0]
			}
			fakeProvider(t, respond(invalid))
			if ok, err := c.http.do(context.Background(), id, sampleVars(c, secret)); ok || err != nil {
				t.Fatalf("invalid response: got (%v, %v), want (false, nil)", ok, err)
			}
			fakeProvider(t, respond(tokenverify.Rule{Status: http.StatusServiceUnavailable}))
			if ok, err := c.http.do(context.Background(), id, sampleVars(c, secret)); ok || err == nil {
				t.Fatalf("503: got (%v, %v), want transient error", ok, err)
			}
		})
	}
}

// A partner-derived endpoint outside the provider's domain is refused
// before any request, so a scanned file cannot redirect the secret.
func TestPartnerHostAllowlist(t *testing.T) {
	cp := fakeProvider(t, respond(tokenverify.Rule{Status: 200}))
	c := checks["betterleaks.salesforce-access-token.1"]
	ok, err := c.http.do(context.Background(), "sf", vars{"secret": "x", "host": "attacker.example"})
	if ok || err == nil {
		t.Fatalf("got (%v, %v), want refusal", ok, err)
	}
	if r, _ := cp.get(); r != nil {
		t.Fatal("request sent to an off-provider host")
	}
}

func TestResolvePartnersNearestAndMissing(t *testing.T) {
	c := &check{partners: p("id", `\b(MA[A-Z0-9]{18})\b`, "?opt", `opt=(\w+)`)}
	data := []byte("PLIVO_ID=MAFARAWAYFARAWAYFAR01\n\n\n\n\n\nPLIVO_ID=MANEARBYNEARBYNEARB1\nPLIVO_TOKEN=tok123\n")
	v, err := c.resolve("tok123", data)
	if err != nil || v["id"] != "MANEARBYNEARBYNEARB1" {
		t.Fatalf("got %v, %v; want the nearest id", v, err)
	}
	if _, ok := v["opt"]; ok {
		t.Fatal("absent optional partner was set")
	}
	if _, err := c.resolve("tok123", []byte("PLIVO_TOKEN=tok123")); err == nil {
		t.Fatal("missing required partner must be an error, never a rejection")
	}
	ok, err := checks["betterleaks.plivo-auth-token"].verify(context.Background(), detectors.Plivo, "plivo", "tok", []byte("tok"))
	if ok || err == nil {
		t.Fatalf("verify without partner: got (%v, %v), want indeterminate", ok, err)
	}
}

type recorder struct{ got []string }

func (r *recorder) Verify(_ context.Context, s string) (bool, error) {
	r.got = append(r.got, s)
	return true, nil
}

// Paired rules pack partners into the provider verifier's secret shape.
func TestBaseChecksComposeProviderShape(t *testing.T) {
	rec := &recorder{}
	old := baseVerifier
	baseVerifier = func(detectors.DetectorType) (detectors.Verifier, detectors.VerificationAssurance, bool) {
		return rec, detectors.AssuranceProviderConfirmed, true
	}
	t.Cleanup(func() { baseVerifier = old })
	cases := []struct{ id, secret, data, want string }{
		{"betterleaks.aws-access-token", "AKIAIOSFODNN7EXAMPLE", "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"betterleaks.azure-ad-client-secret", "abc8Q~secretsecretsecretsecretsecret12", "AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555\nAZURE_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\nAZURE_CLIENT_SECRET=abc8Q~secretsecretsecretsecretsecret12\n", "11111111-2222-3333-4444-555555555555:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:abc8Q~secretsecretsecretsecretsecret12"},
		{"betterleaks.cloudinary-api-secret", "Zx8Yw7Vu6Ts5Rq4Po3Nm2Lk1Jh0GfEd", "CLOUDINARY_CLOUD_NAME=democloud\nCLOUDINARY_API_KEY=123456789012345\nCLOUDINARY_API_SECRET=Zx8Yw7Vu6Ts5Rq4Po3Nm2Lk1Jh0GfEd\n", "123456789012345:Zx8Yw7Vu6Ts5Rq4Po3Nm2Lk1Jh0GfEd@democloud"},
		{"betterleaks.artifactory-api-key", "AKCptoken", "url=https://acme.jfrog.io/artifactory key=AKCptoken", "acme.jfrog.io|AKCptoken"},
		{"betterleaks.github-oauth", "gho_x", "gho_x", "gho_x"},
	}
	for _, tc := range cases {
		rec.got = nil
		ok, err := checks[tc.id].verify(context.Background(), ruleType[tc.id], tc.id, tc.secret, []byte(tc.data))
		if !ok || err != nil || len(rec.got) != 1 || rec.got[0] != tc.want {
			t.Errorf("%s: got (%v, %v) %q, want %q", tc.id, ok, err, rec.got, tc.want)
		}
	}
}

func TestEveryCheckIsWellFormed(t *testing.T) {
	for id, c := range checks {
		n := 0
		for _, set := range []bool{c.base != "", c.http != nil, c.fn != nil} {
			if set {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: want exactly one of base/http/fn, got %d", id, n)
		}
		if c.base == "" && c.assurance == detectors.AssuranceUnknown {
			t.Errorf("%s: no assurance declared", id)
		}
		if c.http != nil && (strings.HasPrefix(c.http.URL, "{") || strings.HasPrefix(c.http.URL, "https://{")) && len(c.http.Hosts) == 0 {
			t.Errorf("%s: partner-derived endpoint without a host allowlist", id)
		}
		for name, pat := range c.partners {
			if _, err := regexp.Compile(pat); err != nil {
				t.Errorf("%s partner %s: %v", id, name, err)
			}
		}
		if _, ok := ruleType[id]; !ok {
			t.Errorf("%s: no catalog rule", id)
		}
	}
}

// The engine-facing contract: a check is wired onto its format, and a
// host with checks is registered as a Verifier with a declared policy.
func TestChecksWiredAndHostsVerify(t *testing.T) {
	for id := range checks {
		t.Run(id, func(t *testing.T) {
			var f *detectors.Format
			for _, x := range detectors.FormatsFor(ruleType[id]) {
				if x.ID == id {
					f = x
				}
			}
			for _, h := range Hosts() {
				for _, x := range h.formats {
					if x.ID == id {
						f = x
					}
				}
			}
			if f == nil || f.Verify == nil {
				t.Fatal("check not attached to its format")
			}
		})
	}
	for _, h := range Hosts() {
		d, _ := detectors.Registered(h.Type())
		_, isV := d.(detectors.Verifier)
		if isV != h.Verifies() {
			t.Errorf("%s: registered verifier=%v, host says %v", h.Type(), isV, h.Verifies())
		}
		if isV {
			if p, ok := d.(detectors.VerificationPolicy); !ok || p.MaxVerificationAssurance() == detectors.AssuranceUnknown {
				t.Errorf("%s: verifier without assurance policy", h.Type())
			}
		}
	}
}

func TestHostVerifySelectsRuleByPrefix(t *testing.T) {
	var devin *verifyingHost
	for _, h := range Hosts() {
		if h.Type() == detectors.Devin {
			devin = h.detector().(*verifyingHost)
		}
	}
	cp := fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.URL.Path == "/v3/self" {
			_, _ = io.WriteString(w, `{"principal_type":"service_user"}`)
			return
		}
		_, _ = io.WriteString(w, `{"sessions":[]}`)
	})
	if ok, err := devin.Verify(context.Background(), "cog_abc"); !ok || err != nil {
		t.Fatalf("cog_: got (%v, %v)", ok, err)
	}
	if r, _ := cp.get(); r.URL.Path != "/v3/self" {
		t.Fatalf("cog_ token routed to %s", r.URL.Path)
	}
	if ok, err := devin.Verify(context.Background(), "apk_user_abc"); !ok || err != nil {
		t.Fatalf("apk_user_: got (%v, %v)", ok, err)
	}
	if r, _ := cp.get(); r.URL.Path != "/v1/sessions" {
		t.Fatalf("apk_user_ token routed to %s", r.URL.Path)
	}
}

// Host FromData verifies with the surrounding window, including partners.
func TestHostFromDataVerifiesWithPartner(t *testing.T) {
	var ramp detectors.Detector
	for _, h := range Hosts() {
		if h.Type() == detectors.Ramp {
			ramp = h.detector()
		}
	}
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = io.WriteString(w, `{"access_token":"t"}`)
	})
	id := "ramp_id_" + strings.Repeat("Ab3", 13) + "Z"
	sec := "ramp_sec_" + "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lz9Xc8Vb7Nm6Pq5Rs4Tu3Vw2Yx1"[:48]
	data := []byte("RAMP_CLIENT_ID=" + id + "\nRAMP_CLIENT_SECRET=" + sec + "\n")
	res, err := ramp.FromData(context.Background(), true, data)
	if err != nil || len(res) == 0 {
		t.Fatalf("got %v, %v", res, err)
	}
	r := res[0]
	if !r.Verified || r.VerificationAssurance != detectors.AssuranceResponseConfirmed || r.ExtraData["verification"] != "format" {
		t.Fatalf("unexpected verdict %+v", r)
	}
	req, _ := cp.get()
	if u, pw, _ := req.BasicAuth(); u != id || pw != string(r.Raw) {
		t.Fatalf("basic auth %q:%q, want client id and secret", u, pw)
	}
	if res, _ := ramp.FromData(context.Background(), false, data); res[0].Verified || res[0].ExtraData["verification"] != "not-attempted" {
		t.Fatalf("verify=false must not verify: %+v", res[0])
	}
}

func fixedNow(t *testing.T) time.Time {
	t.Helper()
	ts := time.Unix(1_700_000_000, 0)
	old := now
	now = func() time.Time { return ts }
	t.Cleanup(func() { now = old })
	return ts
}

func TestAlibabaSignature(t *testing.T) {
	fixedNow(t)
	const secret = "testsecretkeyvalue1234567890ab"
	fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		q := r.URL.Query()
		sig := q.Get("Signature")
		q.Del("Signature")
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = alibabaPercent(k) + "=" + alibabaPercent(q.Get(k))
		}
		m := hmac.New(sha1.New, []byte(secret+"&"))
		m.Write([]byte("GET&%2F&" + alibabaPercent(strings.Join(parts, "&"))))
		if q.Get("AccessKeyId") != "LTAIabcdefghijklmnopq" || q.Get("SecurityToken") != "CAIStoken" ||
			base64.StdEncoding.EncodeToString(m.Sum(nil)) != sig {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"Code":"SignatureDoesNotMatch"}`)
			return
		}
		_, _ = io.WriteString(w, `{"Arn":"acs:ram::1:user/x"}`)
	})
	if ok, err := alibaba(context.Background(), vars{"secret": secret, "id": "LTAIabcdefghijklmnopq", "token": "CAIStoken"}); !ok || err != nil {
		t.Fatalf("got (%v, %v)", ok, err)
	}
	if ok, err := alibaba(context.Background(), vars{"secret": "wrong", "id": "LTAIabcdefghijklmnopq", "token": "CAIStoken"}); ok || err != nil {
		t.Fatalf("bad signature: got (%v, %v), want (false, nil)", ok, err)
	}
}

func TestExoscalePolymarketPackagistOVHSignatures(t *testing.T) {
	ts := fixedNow(t)
	hm := func(key []byte, msg string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(msg))
		return m.Sum(nil)
	}
	t.Run("exoscale", func(t *testing.T) {
		exp := ts.Add(5 * time.Minute).Unix()
		want := "EXO2-HMAC-SHA256 credential=EXOkey,expires=" + itoa(exp) + ",signature=" +
			base64.StdEncoding.EncodeToString(hm([]byte("sk"), "GET /v2/zone\n\n\n\n"+itoa(exp)))
		checkHeader(t, "Authorization", want, func() (bool, error) {
			return exoscale(context.Background(), vars{"secret": "EXOkey", "secretkey": "sk"})
		})
	})
	t.Run("polymarket", func(t *testing.T) {
		key := []byte("0123456789abcdef0123456789abcdef")
		want := base64.URLEncoding.EncodeToString(hm(key, itoa(ts.Unix())+"GET/data/orders"))
		checkHeader(t, "POLY_BUILDER_SIGNATURE", want, func() (bool, error) {
			return polymarket(context.Background(), vars{"secret": "k", "apisecret": base64.URLEncoding.EncodeToString(key), "passphrase": "pp"})
		})
	})
	t.Run("packagist", func(t *testing.T) {
		fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			a := r.Header.Get("Authorization")
			m := detectors.MustCompile(`^PACKAGIST-HMAC-SHA256 Key=(\S+), Timestamp=(\d+), Cnonce=(\w+), Signature=(\S+)$`).FindStringSubmatch(a)
			if m == nil {
				w.WriteHeader(401)
				return
			}
			params := "cnonce=" + m[3] + "&key=" + m[1] + "&timestamp=" + m[2]
			if base64.StdEncoding.EncodeToString(hm([]byte("acs"), "GET\npackagist.com\n/api/packages/\n"+params)) != m[4] {
				w.WriteHeader(401)
				return
			}
			_, _ = io.WriteString(w, `[]`)
		})
		if ok, err := packagistHMAC(context.Background(), vars{"secret": "acs", "key": "packagist_ack_1"}); !ok || err != nil {
			t.Fatalf("got (%v, %v)", ok, err)
		}
	})
	t.Run("ovh", func(t *testing.T) {
		var hosts []string
		fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			hosts = append(hosts, r.Host)
			u := "https://" + r.Host + "/1.0/auth/details"
			sum := sha1.Sum([]byte("as+ck+GET+" + u + "++" + r.Header.Get("X-Ovh-Timestamp"))) //nolint:gosec // scheme
			if r.Host != "ca.api.ovh.com" || r.Header.Get("X-Ovh-Signature") != "$1$"+hex.EncodeToString(sum[:]) {
				w.WriteHeader(403)
				return
			}
			_, _ = io.WriteString(w, `{}`)
		})
		if ok, err := ovh(context.Background(), vars{"secret": "as", "consumer": "ck", "appkey": "ak"}); !ok || err != nil || len(hosts) != 2 {
			t.Fatalf("got (%v, %v) after %v", ok, err, hosts)
		}
	})
}

func itoa(i int64) string { return big.NewInt(i).String() }

func checkHeader(t *testing.T, name, want string, call func() (bool, error)) {
	t.Helper()
	fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.Header.Get(name) != want {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	})
	if ok, err := call(); !ok || err != nil {
		t.Fatalf("got (%v, %v)", ok, err)
	}
}

func TestAzureSchemes(t *testing.T) {
	fixedNow(t)
	key := base64.StdEncoding.EncodeToString([]byte("appconfig-secret-key"))
	t.Run("appconfig", func(t *testing.T) {
		fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			sts := "GET\n" + r.URL.RequestURI() + "\n" + r.Header.Get("x-ms-date") + ";" + r.Host + ";" + r.Header.Get("x-ms-content-sha256")
			m := hmac.New(sha256.New, []byte("appconfig-secret-key"))
			m.Write([]byte(sts))
			want := "HMAC-SHA256 Credential=cred-id&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=" + base64.StdEncoding.EncodeToString(m.Sum(nil))
			if r.Header.Get("Authorization") != want {
				w.WriteHeader(401)
				return
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
		})
		if ok, err := azureAppConfig(context.Background(), vars{"secret": key, "endpoint": "https://store.azconfig.io", "id": "cred-id"}); !ok || err != nil {
			t.Fatalf("got (%v, %v)", ok, err)
		}
		if _, err := azureAppConfig(context.Background(), vars{"secret": key, "endpoint": "https://evil.example", "id": "x"}); err == nil {
			t.Fatal("off-provider endpoint accepted")
		}
	})
	t.Run("servicebus", func(t *testing.T) {
		fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			a := r.Header.Get("Authorization")
			q, _ := url.ParseQuery(strings.TrimPrefix(a, "SharedAccessSignature "))
			m := hmac.New(sha256.New, []byte("sbkey"))
			m.Write([]byte(url.QueryEscape(q.Get("sr")) + "\n" + q.Get("se")))
			if q.Get("skn") != "RootManageSharedAccessKey" || q.Get("sig") != base64.StdEncoding.EncodeToString(m.Sum(nil)) {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, `<Error>InvalidSignature</Error>`)
				return
			}
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `<Error>Manage,EntityRead claims required for this operation.</Error>`)
		})
		cs := "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=sbkey"
		if ok, err := azureServiceBus(context.Background(), vars{"secret": cs}); !ok || err != nil {
			t.Fatalf("authenticated-but-unprivileged key: got (%v, %v)", ok, err)
		}
		bad := strings.Replace(cs, "sbkey", "other", 1)
		if ok, err := azureServiceBus(context.Background(), vars{"secret": bad}); ok || err != nil {
			t.Fatalf("bad key: got (%v, %v), want (false, nil)", ok, err)
		}
	})
}

func TestJWTIssuerSignature(t *testing.T) {
	fixedNow(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	seg := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	mint := func(claims map[string]any, k *rsa.PrivateKey) string {
		in := seg(map[string]string{"alg": "RS256", "kid": "k1"}) + "." + seg(claims)
		d := sha256.Sum256([]byte(in))
		s, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		return in + "." + base64.RawURLEncoding.EncodeToString(s)
	}
	fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = io.WriteString(w, `{"jwks_uri":"https://issuer.example/jwks"}`)
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		}
	})
	good := mint(map[string]any{"iss": "https://issuer.example", "exp": 1_800_000_000}, key)
	if ok, err := jwtIssuer(context.Background(), vars{"secret": good}); !ok || err != nil {
		t.Fatalf("issuer-signed: got (%v, %v)", ok, err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if ok, err := jwtIssuer(context.Background(), vars{"secret": mint(map[string]any{"iss": "https://issuer.example"}, other)}); ok || err != nil {
		t.Fatalf("forged: got (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := jwtIssuer(context.Background(), vars{"secret": mint(map[string]any{"iss": "https://issuer.example", "exp": 1}, key)}); ok || err != nil {
		t.Fatalf("expired: got (%v, %v), want (false, nil)", ok, err)
	}
	if _, err := jwtIssuer(context.Background(), vars{"secret": mint(map[string]any{"sub": "x"}, key)}); err == nil {
		t.Fatal("token without an issuer must be indeterminate")
	}
}

func TestMiscSchemes(t *testing.T) {
	t.Run("secp256k1", func(t *testing.T) {
		for in, want := range map[string]bool{
			"0x" + strings.Repeat("11", 32): true,
			strings.Repeat("00", 32):        false,
			strings.Repeat("ff", 32):        false,
			"0xzz":                          false,
		} {
			if got, _ := secp256k1Scalar(context.Background(), vars{"secret": in}); got != want {
				t.Errorf("%s: got %v", in, got)
			}
		}
	})
	t.Run("gitURL", func(t *testing.T) {
		cp := fakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			if u, p, _ := r.BasicAuth(); u != "user" || p != "p@ss" {
				w.WriteHeader(401)
			}
		})
		ok, err := gitURL("bitbucket.org", 200)(context.Background(), vars{"secret": "https://user:p%40ss@bitbucket.org/team/repo.git"})
		if !ok || err != nil {
			t.Fatalf("got (%v, %v)", ok, err)
		}
		if r, _ := cp.get(); r.URL.Path != "/team/repo.git/info/refs" || r.URL.RawQuery != "service=git-upload-pack" {
			t.Fatalf("probe %s", r.URL)
		}
		if _, err := gitURL("bitbucket.org", 200)(context.Background(), vars{"secret": "https://u:p@evil.example/x.git"}); err == nil {
			t.Fatal("off-provider git URL accepted")
		}
	})
	t.Run("cloudflare", func(t *testing.T) {
		cp := fakeProvider(t, respond(st(200, `"status":"active"`)))
		if _, err := cloudflareToken(context.Background(), vars{"secret": "cfat_x"}); err == nil {
			t.Fatal("account token without account id must be indeterminate")
		}
		if ok, err := cloudflareToken(context.Background(), vars{"secret": "cfat_x", "account": "abc"}); !ok || err != nil {
			t.Fatalf("got (%v, %v)", ok, err)
		}
		if r, _ := cp.get(); r.URL.Path != "/client/v4/accounts/abc/tokens/verify" {
			t.Fatalf("path %s", r.URL.Path)
		}
	})
	t.Run("workato region", func(t *testing.T) {
		cp := fakeProvider(t, respond(st(200)))
		if ok, _ := workato(context.Background(), vars{"secret": "wrkaeu-eyJx"}); !ok {
			t.Fatal("not verified")
		}
		if r, _ := cp.get(); r.Host != "app.eu.workato.com" {
			t.Fatalf("host %s", r.Host)
		}
	})
	t.Run("gcp adc", func(t *testing.T) {
		cp := fakeProvider(t, respond(st(200, `"access_token":"x"`)))
		adc := `{"client_id":"1.apps.googleusercontent.com","client_secret":"cs","refresh_token":"rt","type":"authorized_user"}`
		if ok, err := gcpADC(context.Background(), vars{"secret": adc}); !ok || err != nil {
			t.Fatalf("got (%v, %v)", ok, err)
		}
		if _, body := cp.get(); !strings.Contains(body, "refresh_token=rt") {
			t.Fatalf("body %q", body)
		}
	})
}

func TestPublicIPGuard(t *testing.T) {
	for ip, want := range map[string]bool{"8.8.8.8": true, "127.0.0.1": false, "10.1.2.3": false, "169.254.169.254": false, "100.64.0.1": false, "::1": false} {
		if publicIP(net.ParseIP(ip)) != want {
			t.Errorf("%s: want public=%v", ip, want)
		}
	}
}

func hostDetector(t *testing.T, ty detectors.DetectorType) detectors.Detector {
	t.Helper()
	for _, h := range Hosts() {
		if h.Type() == ty {
			return h.detector()
		}
	}
	t.Fatalf("%s host missing", ty)
	return nil
}

// pleno-only checks (issue #950): partners resolve from the window, and a
// partner-derived host stays on the provider's domain.
func TestPlenoOnlyPartnerChecks(t *testing.T) {
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = io.WriteString(w, `{"users":[],"sys":{"type":"Space"},"token":"t"}`)
	})
	app := "0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9"
	tok := "9f3a71c2e8b54d06a1f7c3e92b8d4605fa1e7c39"
	res, err := hostDetector(t, detectors.Sendbird).FromData(context.Background(), true,
		[]byte("SENDBIRD_APP_ID="+app+"\nSENDBIRD_ACCESS_TOKEN="+tok+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	verified := false
	for _, r := range res {
		if string(r.Raw) == tok && r.Verified {
			verified = true
		}
	}
	req, _ := cp.get()
	if !verified || req == nil || req.Host != "api-"+app+".sendbird.com" || req.Header.Get("Api-Token") != tok {
		t.Fatalf("sendbird: verified=%v req=%v", verified, req)
	}
	ok, err := checks["betterleaks.sendbird-access-token"].http.do(context.Background(), "sb",
		vars{"secret": tok, "app": "x.attacker.example/"})
	if ok || err == nil {
		t.Fatalf("sendbird off-domain app id: got (%v, %v), want refusal", ok, err)
	}

	space := "abcdef012345"
	ctok := "Xq9_rT4mLp2wZk7vB1nC8yH3jD6fG0sA5eU-iO7kM2t"
	res, err = hostDetector(t, detectors.Contentful).FromData(context.Background(), true,
		[]byte("CONTENTFUL_SPACE_ID="+space+"\nCONTENTFUL_ACCESS_TOKEN="+ctok+"\n"))
	if err != nil || len(res) == 0 || !res[0].Verified {
		t.Fatalf("contentful: %+v %v", res, err)
	}
	if req, _ := cp.get(); req.URL.Path != "/spaces/"+space {
		t.Fatalf("contentful path %s", req.URL.Path)
	}
}

func TestPlenoOnlyHostVerifyByPrefix(t *testing.T) {
	cp := fakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		_, _ = io.WriteString(w, `{"clouds":[]}`)
	})
	y := hostDetector(t, detectors.Yandex).(detectors.Verifier)
	if ok, err := y.Verify(context.Background(), "AQVNabc"); !ok || err != nil {
		t.Fatalf("yandex api key: (%v, %v)", ok, err)
	}
	if r, _ := cp.get(); r.Header.Get("Authorization") != "Api-Key AQVNabc" {
		t.Fatalf("yandex api key header %q", r.Header.Get("Authorization"))
	}
	if ok, err := y.Verify(context.Background(), "t1.abc"); !ok || err != nil {
		t.Fatalf("yandex iam token: (%v, %v)", ok, err)
	}
	if r, _ := cp.get(); r.Header.Get("Authorization") != "Bearer t1.abc" {
		t.Fatalf("yandex iam header %q", r.Header.Get("Authorization"))
	}
	if _, err := y.Verify(context.Background(), "YCunknown"); err == nil {
		t.Fatal("static access key without a check must be indeterminate")
	}
}
