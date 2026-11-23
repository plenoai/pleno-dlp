package alibaba

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func verifySig(r *http.Request, secret string) bool {
	raw := r.URL.RawQuery
	i := strings.LastIndex(raw, "&Signature=")
	if i < 0 {
		return false
	}
	canon, sig := raw[:i], raw[i+len("&Signature="):]
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte("GET&%2F&" + pct(canon)))
	return pct(base64.StdEncoding.EncodeToString(mac.Sum(nil))) == sig
}

func TestRAMUser(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verifySig(r, "sec") || r.URL.Query().Get("AccessKeyId") != "LTAI1" {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Query().Get("Action") {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`{"AccountId":"123","Arn":"acs:ram::123:user/alice","IdentityType":"RAMUser","UserId":"u"}`))
		case "ListPoliciesForUser":
			if r.URL.Query().Get("UserName") != "alice" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{"Policies":{"Policy":[{"PolicyName":"AliyunOSSReadOnlyAccess","PolicyType":"System"},{"PolicyName":"AdministratorAccess","PolicyType":"System"}]}}`))
		}
	}))
	defer s.Close()
	am, err := Mapper{STSURL: s.URL, RAMURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "LTAI1", Secondary: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	if am.Identity.Name != "alice" || am.Identity.Type != "ramuser" || !am.Privileged ||
		!slices.Equal(am.Permissions, []string{"policy:AliyunOSSReadOnlyAccess", "policy:AdministratorAccess"}) {
		t.Fatalf("%+v", am)
	}
	if _, err := (Mapper{STSURL: s.URL}).MapAccess(context.Background(), detectors.AccessCredential{Secret: "LTAI1", Secondary: "bad"}); err == nil {
		t.Fatal("bad signature must fail")
	}
}
