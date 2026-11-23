package catalog

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Partner patterns for the catalog hosts that need a second value from
// the surrounding text (issue #956). Each mirrors the betterleaks
// assignment shape of its sibling rule.
const (
	pFinicityAppKey    = `(?i)(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pFinicitySecret    = `(?i)(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pFinicityPartnerID = `(?i)(?:partner[_. -]*id)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{4,20})(?:\\?['"\x60]|[\s;,]|\\[nr]|$)`
	pFreemiusID        = `(?i)["']id["']\s*=>\s*["']?([0-9]{1,12})\b`
	pFreemiusPublic    = `(?i)["']public_key["']\s*=>\s*["'](pk_[A-Za-z0-9]{20,40})["']`
	pKuCoinKey         = `(?i)(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{24})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pKuCoinSecret      = `(?i)(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pKuCoinPassphrase  = `(?i)(?:kucoin[ \t\w.-]{0,20}pass(?:phrase|word)?)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([^\s'"\x60;]{1,64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pLinkedInClientID  = `(?i)(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{14})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	// SettleMint deployment and console URLs live under settlemint.com;
	// the check's host allowlist pins the same domain.
	pSettleMintURL = `(?i)\b(https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.settlemint\.com)\b`
)

// finicity authenticates the partner with App-Key, partner ID, and
// partner secret; an issued token is provider-confirmed.
func finicity(secretVar, keyVar string) *httpCheck {
	return post("https://api.finicity.com/aggregation/v2/partners/authentication", "application/json",
		`{"partnerId":{partner|json},"partnerSecret":{`+secretVar+`|json}}`,
		map[string]string{"Finicity-App-Key": "{" + keyVar + "}", "Accept": "application/json"},
		st(200, `"token"`)).invalid(st(401), st(403))
}

// linkedin exchanges a bogus authorization code: LinkedIn authenticates
// the client first, so "invalid_client" rejects the secret and any other
// OAuth error means the client id/secret pair was accepted.
func linkedin() *httpCheck {
	return post("https://www.linkedin.com/oauth/v2/accessToken", form,
		"grant_type=authorization_code&code=pleno_dlp_invalid_code&redirect_uri=https%3A%2F%2Fexample.com%2Fpleno-dlp&client_id={client|url}&client_secret={secret|url}",
		map[string]string{"Accept": "application/json"},
		tokenverify.Rule{Status: 400, BodyContains: `"invalid_request"`, BodyNotContains: `"invalid_client"`},
		tokenverify.Rule{Status: 400, BodyContains: `"invalid_grant"`, BodyNotContains: `"invalid_client"`}).
		invalid(st(0, `"invalid_client"`))
}

// settlemint sends the token to a settlemint.com deployment or console
// URL found next to it; the platform gateway rejects unknown tokens
// before routing, so any routed answer is response-confirmed.
func settlemint() *httpCheck {
	return get("{url}", map[string]string{"x-auth-token": "{secret}", "Accept": "application/json"},
		st(200), st(404)).invalid(st(401), st(403)).hosts("settlemint.com")
}

// freemius signs GET /v1/plugins/{id}.json with the Freemius API scheme
// (freemius/freemius-php-sdk): HMAC-SHA256 over method, content MD5,
// content type, date, and resource path, hex digest base64url-encoded.
func freemius(ctx context.Context, v vars) (bool, error) {
	id := v["id"]
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return false, errors.New("freemius verify: plugin id is not numeric")
	}
	path := "/v1/plugins/" + id + ".json"
	date := now().UTC().Format(time.RFC1123Z)
	req, err := newReq(ctx, http.MethodGet, "https://api.freemius.com"+path, "")
	if err != nil {
		return false, errors.New("freemius verify: build request")
	}
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", "FS "+id+":"+v["public"]+":"+freemiusSign(v["secret"], http.MethodGet, date, path))
	req.Header.Set("Accept", "application/json")
	return do("Freemius", req, []tokenverify.Rule{st(200, `"id"`)}, []tokenverify.Rule{st(401), st(403)})
}

func freemiusSign(secret, method, date, path string) string {
	sts := strings.Join([]string{method, "", "", date, path}, "\n")
	sum := hex.EncodeToString(hmacSum(sha256.New, []byte(secret), []byte(sts)))
	return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString([]byte(sum))), "=")
}

// kucoin signs GET /api/v1/accounts with API key version 2 (HMAC-SHA256
// over timestamp+method+path; the passphrase is HMAC'd with the secret).
// secretIsKey selects which credential the candidate is: the API key
// (partners: sk, passphrase) or the API secret (partners: key,
// passphrase). Only the error code that names the candidate itself
// rejects it; a bad passphrase or partner stays indeterminate.
func kucoin(secretIsKey bool) func(context.Context, vars) (bool, error) {
	return func(ctx context.Context, v vars) (bool, error) {
		key, sk, reject := v["key"], v["secret"], `"400005"` // signature invalid: the secret is wrong
		if secretIsKey {
			key, sk, reject = v["secret"], v["sk"], `"400003"` // API key does not exist
		}
		const path = "/api/v1/accounts"
		ts := strconv.FormatInt(now().UnixMilli(), 10)
		req, err := newReq(ctx, http.MethodGet, "https://api.kucoin.com"+path, "")
		if err != nil {
			return false, errors.New("kucoin verify: build request")
		}
		req.Header.Set("KC-API-KEY", key)
		req.Header.Set("KC-API-SIGN", kucoinB64(sk, ts+http.MethodGet+path))
		req.Header.Set("KC-API-TIMESTAMP", ts)
		req.Header.Set("KC-API-PASSPHRASE", kucoinB64(sk, v["passphrase"]))
		req.Header.Set("KC-API-KEY-VERSION", "2")
		req.Header.Set("Accept", "application/json")
		return do("KuCoin", req, []tokenverify.Rule{st(200, `"code":"200000"`)}, []tokenverify.Rule{st(0, reject)})
	}
}

func kucoinB64(key, msg string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}
