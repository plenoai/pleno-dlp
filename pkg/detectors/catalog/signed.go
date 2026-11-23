package catalog

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // provider-mandated signature schemes (Alibaba RPC, OVH)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// now is overridable in tests.
var now = time.Now

func hmacSum(h func() hash.Hash, key, msg []byte) []byte {
	m := hmac.New(h, key)
	m.Write(msg)
	return m.Sum(nil)
}

// do sends req and classifies the response.
func do(name string, req *http.Request, valid, invalid []tokenverify.Rule) (bool, error) {
	status, body, err := send(req)
	if err != nil {
		return false, fmt.Errorf("%s verify: %w", name, err)
	}
	return tokenverify.Classify(name, status, body, valid, invalid)
}

func newReq(ctx context.Context, method, u string, body string) (*http.Request, error) {
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	if r == nil {
		return http.NewRequestWithContext(ctx, method, u, nil)
	}
	return http.NewRequestWithContext(ctx, method, u, r)
}

// alibabaPercent is Alibaba's RPC percent-encoding (RFC 3986 unreserved).
func alibabaPercent(s string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(s))
}

// alibaba signs STS GetCallerIdentity with HMAC-SHA1 (RPC signature v1.0);
// an ARN in the response is the caller's identity.
func alibaba(ctx context.Context, v vars) (bool, error) {
	params := map[string]string{
		"AccessKeyId":      v["id"],
		"Action":           "GetCallerIdentity",
		"Format":           "JSON",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   strconv.FormatInt(now().UnixNano(), 10),
		"SignatureVersion": "1.0",
		"Timestamp":        now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2015-04-01",
	}
	if t := v["token"]; t != "" {
		params["SecurityToken"] = t
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = alibabaPercent(k) + "=" + alibabaPercent(params[k])
	}
	canon := strings.Join(parts, "&")
	sig := base64.StdEncoding.EncodeToString(hmacSum(sha1.New, []byte(v["secret"]+"&"), []byte("GET&%2F&"+alibabaPercent(canon))))
	req, err := newReq(ctx, http.MethodGet, "https://sts.aliyuncs.com/?"+canon+"&Signature="+alibabaPercent(sig), "")
	if err != nil {
		return false, errors.New("alibaba verify: build request")
	}
	req.Header.Set("Accept", "application/json")
	return do("AlibabaCloud", req,
		[]tokenverify.Rule{st(200, `"Arn"`)},
		[]tokenverify.Rule{st(401), st(403), st(0, "InvalidAccessKeyId"), st(0, "SignatureDoesNotMatch")})
}

// azureAppConfig signs a key listing with the App Configuration
// HMAC-SHA256 scheme taken from the connection string.
func azureAppConfig(ctx context.Context, v vars) (bool, error) {
	endpoint, id, secret, ok := parseAppConfig(v["secret"])
	if !ok {
		// The format captures only the Secret= value; endpoint and id come
		// from the same connection string.
		endpoint, id, secret = v["endpoint"], v["id"], v["secret"]
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || !hostAllowed(u.Hostname(), []string{"azconfig.io"}) {
		return false, errors.New("AzureAppConfiguration verify: endpoint outside azconfig.io")
	}
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return false, errors.New("AzureAppConfiguration verify: secret is not base64")
	}
	const pathQuery = "/keys?api-version=1.0"
	date := now().UTC().Format(http.TimeFormat)
	empty := sha256.Sum256(nil)
	hashB64 := base64.StdEncoding.EncodeToString(empty[:])
	sts := "GET\n" + pathQuery + "\n" + date + ";" + u.Host + ";" + hashB64
	sig := base64.StdEncoding.EncodeToString(hmacSum(sha256.New, key, []byte(sts)))
	req, err := newReq(ctx, http.MethodGet, "https://"+u.Host+pathQuery, "")
	if err != nil {
		return false, errors.New("AzureAppConfiguration verify: build request")
	}
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-content-sha256", hashB64)
	req.Header.Set("Authorization", "HMAC-SHA256 Credential="+id+"&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+sig)
	return do("AzureAppConfiguration", req, []tokenverify.Rule{st(200)}, []tokenverify.Rule{st(401), st(403)})
}

func connParts(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok {
			out[strings.ToLower(k)] = val
		}
	}
	return out
}

// parseAppConfig splits a full App Configuration connection string.
func parseAppConfig(s string) (endpoint, id, secret string, ok bool) {
	m := connParts(s)
	endpoint, id, secret = m["endpoint"], m["id"], m["secret"]
	return endpoint, id, secret, endpoint != "" && id != "" && secret != ""
}

// azureServiceBus signs a SAS token for the namespace and lists queues.
// A 401 naming a missing claim proves the key signed correctly but lacks
// Manage rights, which is still a live credential.
func azureServiceBus(ctx context.Context, v vars) (bool, error) {
	m := connParts(v["secret"])
	ep, name, key := m["endpoint"], m["sharedaccesskeyname"], m["sharedaccesskey"]
	u, err := url.Parse(ep)
	if err != nil || u.Scheme != "sb" || !hostAllowed(u.Hostname(), []string{"servicebus.windows.net"}) || name == "" || key == "" {
		return false, errors.New("AzureServiceBus verify: malformed connection string")
	}
	resource := "https://" + u.Hostname() + "/"
	if e := m["entitypath"]; e != "" {
		resource += e
	}
	exp := strconv.FormatInt(now().Add(5*time.Minute).Unix(), 10)
	encRes := url.QueryEscape(resource)
	sig := base64.StdEncoding.EncodeToString(hmacSum(sha256.New, []byte(key), []byte(encRes+"\n"+exp)))
	token := "SharedAccessSignature sr=" + encRes + "&sig=" + url.QueryEscape(sig) + "&se=" + exp + "&skn=" + url.QueryEscape(name)
	req, err := newReq(ctx, http.MethodGet, "https://"+u.Hostname()+"/$Resources/Queues?api-version=2017-04", "")
	if err != nil {
		return false, errors.New("AzureServiceBus verify: build request")
	}
	req.Header.Set("Authorization", token)
	return do("AzureServiceBus", req,
		[]tokenverify.Rule{st(200), st(401, "claim")},
		[]tokenverify.Rule{st(401), st(403)})
}

// cloudflareToken verifies user tokens (cfut_) at /user/tokens/verify and
// account tokens (cfat_) at /accounts/{id}/tokens/verify; an account
// token without a nearby account id is indeterminate.
func cloudflareToken(ctx context.Context, v vars) (bool, error) {
	path := "/client/v4/user/tokens/verify"
	if strings.HasPrefix(v["secret"], "cfat_") {
		acct := v["account"]
		if acct == "" {
			return false, errors.New("cloudflare verify: account token needs a nearby account id")
		}
		path = "/client/v4/accounts/" + url.PathEscape(acct) + "/tokens/verify"
	}
	req, err := newReq(ctx, http.MethodGet, "https://api.cloudflare.com"+path, "")
	if err != nil {
		return false, errors.New("cloudflare verify: build request")
	}
	req.Header.Set("Authorization", "Bearer "+v["secret"])
	return do("Cloudflare", req,
		[]tokenverify.Rule{st(200, `"status":"active"`)},
		[]tokenverify.Rule{st(200, `"status":"disabled"`), st(200, `"status":"expired"`), st(401), st(403)})
}

// exoscale signs GET /v2/zone with EXO2-HMAC-SHA256.
func exoscale(ctx context.Context, v vars) (bool, error) {
	exp := strconv.FormatInt(now().Add(5*time.Minute).Unix(), 10)
	msg := "GET /v2/zone\n\n\n\n" + exp
	sig := base64.StdEncoding.EncodeToString(hmacSum(sha256.New, []byte(v["secretkey"]), []byte(msg)))
	req, err := newReq(ctx, http.MethodGet, "https://api-ch-gva-2.exoscale.com/v2/zone", "")
	if err != nil {
		return false, errors.New("exoscale verify: build request")
	}
	req.Header.Set("Authorization", "EXO2-HMAC-SHA256 credential="+v["secret"]+",expires="+exp+",signature="+sig)
	return do("Exoscale", req, []tokenverify.Rule{st(200)}, []tokenverify.Rule{st(401), st(403)})
}

// polymarket signs GET /data/orders with the builder HMAC-SHA256 scheme.
func polymarket(ctx context.Context, v vars) (bool, error) {
	secret := v["apisecret"]
	key, err := base64.URLEncoding.DecodeString(secret)
	if err != nil {
		if key, err = base64.StdEncoding.DecodeString(secret); err != nil {
			return false, errors.New("polymarket verify: API secret is not base64")
		}
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	sig := base64.URLEncoding.EncodeToString(hmacSum(sha256.New, key, []byte(ts+"GET/data/orders")))
	req, err := newReq(ctx, http.MethodGet, "https://clob.polymarket.com/data/orders", "")
	if err != nil {
		return false, errors.New("polymarket verify: build request")
	}
	req.Header.Set("POLY_BUILDER_API_KEY", v["secret"])
	req.Header.Set("POLY_BUILDER_PASSPHRASE", v["passphrase"])
	req.Header.Set("POLY_BUILDER_TIMESTAMP", ts)
	req.Header.Set("POLY_BUILDER_SIGNATURE", sig)
	return do("Polymarket", req, []tokenverify.Rule{st(200)}, []tokenverify.Rule{st(401), st(403)})
}

var secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// secp256k1Scalar is kingfisher's offline Ethereum key check: the value
// is a usable private-key scalar (0 < k < n). It proves shape, not
// control of funds, hence heuristic assurance.
func secp256k1Scalar(_ context.Context, v vars) (bool, error) {
	h := strings.TrimPrefix(strings.TrimPrefix(v["secret"], "0x"), "0X")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return false, nil
	}
	k := new(big.Int).SetBytes(b)
	return k.Sign() > 0 && k.Cmp(secp256k1N) < 0, nil
}

// gcpADC exchanges an authorized-user ADC refresh token for an access
// token; issuance demonstrates an authenticated capability.
func gcpADC(ctx context.Context, v vars) (bool, error) {
	var c struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(v["secret"]), &c); err != nil || c.ClientID == "" || c.ClientSecret == "" || c.RefreshToken == "" {
		return false, errors.New("GCPOAuth verify: incomplete application default credentials")
	}
	body := url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "client_secret": {c.ClientSecret}, "refresh_token": {c.RefreshToken}}.Encode()
	req, err := newReq(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", body)
	if err != nil {
		return false, errors.New("GCPOAuth verify: build request")
	}
	req.Header.Set("Content-Type", form)
	return do("GCPOAuth", req, []tokenverify.Rule{st(200, `"access_token"`)},
		[]tokenverify.Rule{st(400, "invalid_grant"), st(400, "invalid_client"), st(401)})
}

// ovh signs GET /1.0/auth/details ($1$ SHA-1 scheme) against each
// regional API, since application keys are region-bound.
func ovh(ctx context.Context, v vars) (bool, error) {
	var lastErr error
	for _, host := range []string{"eu.api.ovh.com", "ca.api.ovh.com", "api.us.ovhcloud.com"} {
		u := "https://" + host + "/1.0/auth/details"
		ts := strconv.FormatInt(now().Unix(), 10)
		sum := sha1.Sum([]byte(v["secret"] + "+" + v["consumer"] + "+GET+" + u + "++" + ts)) //nolint:gosec // OVH signature scheme
		req, err := newReq(ctx, http.MethodGet, u, "")
		if err != nil {
			return false, errors.New("OVHCloud verify: build request")
		}
		req.Header.Set("X-Ovh-Application", v["appkey"])
		req.Header.Set("X-Ovh-Consumer", v["consumer"])
		req.Header.Set("X-Ovh-Timestamp", ts)
		req.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(sum[:]))
		ok, err := do("OVHCloud", req, []tokenverify.Rule{st(200)}, []tokenverify.Rule{st(400), st(401), st(403)})
		if ok {
			return true, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return false, lastErr
}

// packagistHMAC signs GET /api/packages/ with PACKAGIST-HMAC-SHA256.
func packagistHMAC(ctx context.Context, v vars) (bool, error) {
	ts := strconv.FormatInt(now().Unix(), 10)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return false, errors.New("packagist verify: nonce")
	}
	cnonce := hex.EncodeToString(nonce)
	params := "cnonce=" + url.QueryEscape(cnonce) + "&key=" + url.QueryEscape(v["key"]) + "&timestamp=" + url.QueryEscape(ts)
	sig := base64.StdEncoding.EncodeToString(hmacSum(sha256.New, []byte(v["secret"]), []byte("GET\npackagist.com\n/api/packages/\n"+params)))
	req, err := newReq(ctx, http.MethodGet, "https://packagist.com/api/packages/", "")
	if err != nil {
		return false, errors.New("packagist verify: build request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "PACKAGIST-HMAC-SHA256 Key="+v["key"]+", Timestamp="+ts+", Cnonce="+cnonce+", Signature="+sig)
	return do("Packagist", req, []tokenverify.Rule{st(200, "[")}, []tokenverify.Rule{st(401), st(403)})
}

// workato picks the data-center host from the token prefix.
func workato(ctx context.Context, v vars) (bool, error) {
	host := "https://www.workato.com"
	for p, h := range map[string]string{
		"wrkaeu-": "https://app.eu.workato.com", "wrkajp-": "https://app.jp.workato.com",
		"wrkasg-": "https://app.sg.workato.com", "wrkaau-": "https://app.au.workato.com",
		"wrkail-": "https://app.il.workato.com", "wrkacn-": "https://app.workatoapp.cn",
		"wrkakr-": "https://app.kr.workato.com",
	} {
		if strings.HasPrefix(v["secret"], p) {
			host = h
		}
	}
	req, err := newReq(ctx, http.MethodGet, host+"/api/users/me", "")
	if err != nil {
		return false, errors.New("workato verify: build request")
	}
	req.Header.Set("Authorization", "Bearer "+v["secret"])
	return do("Workato", req, []tokenverify.Rule{st(200)}, []tokenverify.Rule{st(401), st(403)})
}

// gitURL verifies https://user:pass@host/repo credentials with a smart-HTTP
// ref advertisement, which only an authenticated client receives.
func gitURL(suffix string, okCodes ...int) func(context.Context, vars) (bool, error) {
	return func(ctx context.Context, v vars) (bool, error) {
		u, err := url.Parse(strings.TrimRight(v["secret"], "\"'`"))
		if err != nil || u.Scheme != "https" || u.User == nil || !hostAllowed(u.Hostname(), []string{suffix}) {
			return false, errors.New("git credential verify: malformed or off-provider URL")
		}
		user := u.User.Username()
		pass, _ := u.User.Password()
		u.User = nil
		u.RawQuery, u.Fragment = "", ""
		u.Path = strings.TrimRight(u.Path, "/") + "/info/refs"
		u.RawQuery = "service=git-upload-pack"
		req, err := newReq(ctx, http.MethodGet, u.String(), "")
		if err != nil {
			return false, errors.New("git credential verify: build request")
		}
		req.SetBasicAuth(user, pass)
		valid := make([]tokenverify.Rule, len(okCodes))
		for i, c := range okCodes {
			valid[i] = st(c)
		}
		return do("git credentials", req, valid, []tokenverify.Rule{st(401), st(403)})
	}
}

// jwtIssuer is kingfisher's JWT validation: an expired token is invalid;
// otherwise the signature must verify against the issuer's OIDC JWKS
// (https, same host as the issuer). A valid signature proves the issuer
// minted the token, not that it is still accepted, hence response-confirmed.
func jwtIssuer(ctx context.Context, v vars) (bool, error) {
	parts := strings.Split(v["secret"], ".")
	if len(parts) != 3 {
		return false, errors.New("JWT verify: not a compact JWS")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	var claims struct {
		Iss string   `json:"iss"`
		Exp *float64 `json:"exp"`
	}
	if err := decodeSeg(parts[0], &hdr); err != nil {
		return false, errors.New("JWT verify: bad header")
	}
	if err := decodeSeg(parts[1], &claims); err != nil {
		return false, errors.New("JWT verify: bad claims")
	}
	if claims.Exp != nil && now().Unix() > int64(*claims.Exp) {
		return false, nil
	}
	iss, err := url.Parse(claims.Iss)
	if err != nil || iss.Scheme != "https" || iss.Host == "" {
		return false, errors.New("JWT verify: no https issuer to discover keys from")
	}
	var cfg struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, strings.TrimRight(claims.Iss, "/")+"/.well-known/openid-configuration", &cfg); err != nil {
		return false, fmt.Errorf("JWT verify: issuer discovery: %w", err)
	}
	ju, err := url.Parse(cfg.JWKSURI)
	if err != nil || ju.Scheme != "https" || !strings.EqualFold(ju.Hostname(), iss.Hostname()) {
		return false, errors.New("JWT verify: jwks_uri must be https on the issuer host")
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := getJSON(ctx, ju.String(), &set); err != nil {
		return false, fmt.Errorf("JWT verify: jwks: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, nil
	}
	signed := []byte(parts[0] + "." + parts[1])
	tried := false
	for _, k := range set.Keys {
		if hdr.Kid != "" && k.Kid != hdr.Kid {
			continue
		}
		ok, usable := k.verify(hdr.Alg, signed, sig)
		tried = tried || usable
		if ok {
			return true, nil
		}
	}
	if !tried {
		return false, errors.New("JWT verify: no issuer key for the token's kid/alg")
	}
	return false, nil
}

func decodeSeg(s string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func getJSON(ctx context.Context, u string, out any) error {
	req, err := newReq(ctx, http.MethodGet, u, "")
	if err != nil {
		return errors.New("build request")
	}
	req.Header.Set("Accept", "application/json")
	status, body, err := send(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("HTTP %d", status)
	}
	return json.Unmarshal(body, out)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64int(s string) *big.Int {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return new(big.Int).SetBytes(b)
}

// verify reports (signature valid, key usable for alg).
func (k jwk) verify(alg string, signed, sig []byte) (bool, bool) {
	hashFor := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}
	if len(alg) != 5 {
		return false, false
	}
	h, ok := hashFor[alg[2:]]
	if !ok {
		return false, false
	}
	var digest []byte
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(signed)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(signed)
		digest = d[:]
	default:
		d := sha512.Sum512(signed)
		digest = d[:]
	}
	switch {
	case strings.HasPrefix(alg, "RS") && k.Kty == "RSA":
		pub := &rsa.PublicKey{N: b64int(k.N), E: int(b64int(k.E).Int64())}
		return rsa.VerifyPKCS1v15(pub, h, digest, sig) == nil, true
	case strings.HasPrefix(alg, "PS") && k.Kty == "RSA":
		pub := &rsa.PublicKey{N: b64int(k.N), E: int(b64int(k.E).Int64())}
		return rsa.VerifyPSS(pub, h, digest, sig, nil) == nil, true
	case strings.HasPrefix(alg, "ES") && k.Kty == "EC":
		curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[k.Crv]
		if curve == nil || len(sig)%2 != 0 {
			return false, false
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: b64int(k.X), Y: b64int(k.Y)}
		half := len(sig) / 2
		return ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:half]), new(big.Int).SetBytes(sig[half:])), true
	}
	return false, false
}
