package catalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// check verifies the candidates of one kingfisher rule (issue #934).
//
// Exactly one of base, http, or fn is set:
//
//   - base routes the candidate to the owning provider's registered
//     Verifier, after composing the provider's packed secret shape
//     (e.g. "{id}:{secret}") from partners. The provider's own
//     MaxVerificationAssurance applies.
//   - http is a declarative single round trip (kingfisher's Http and
//     Betterleaks validators).
//   - fn is a signed or multi-step scheme (SigV4-style HMAC, SAS, OIDC).
//
// partners are kingfisher's depends_on rules: RE2 patterns (first
// participating group is the value) resolved from the candidate's window,
// nearest occurrence first. A missing partner is an indeterminate result,
// never a rejection.
type check struct {
	partners  map[string]string
	base      string
	http      *httpCheck
	fn        func(ctx context.Context, v vars) (bool, error)
	assurance detectors.VerificationAssurance
	// prefix selects this check for a host-level Verify(secret) call when
	// the host has more than one verifiable rule.
	prefix string
}

// vars carries "secret" plus every resolved partner.
type vars map[string]string

// httpCheck is one templated request. Templates substitute {name},
// {name|url} (query-escaped), {name|json} (JSON string literal), and
// {basic:a:b} (base64 of vars a ":" b; a quoted 'literal' may stand in
// for either name).
type httpCheck struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	ContentType string
	// Hosts lists the host suffixes a partner-derived URL may resolve to;
	// required whenever URL starts with a partner variable, so a scanned
	// file cannot point the secret at an arbitrary host.
	Hosts   []string
	Valid   []tokenverify.Rule
	Invalid []tokenverify.Rule
}

const verifyTimeout = 10 * time.Second

// verifyClient refuses redirects and connections to non-public addresses
// (the JWT issuer discovery URL comes from the scanned token).
var verifyClient = newVerifyClient()

func newVerifyClient() *http.Client {
	c := detectors.NewVerifyHTTPClient(verifyTimeout)
	d := &net.Dialer{Timeout: verifyTimeout}
	c.Transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !publicIP(ip.IP) {
					return nil, fmt.Errorf("refusing non-public address for %s", host)
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no address for %s", host)
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSHandshakeTimeout: verifyTimeout,
		ForceAttemptHTTP2:   true,
	}
	return c
}

func publicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		(ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xc0 == 64))
}

// baseVerifier resolves a provider's registered Verifier (overridable in
// tests).
var baseVerifier = func(t detectors.DetectorType) (detectors.Verifier, detectors.VerificationAssurance, bool) {
	d, ok := detectors.Registered(t)
	if !ok {
		return nil, 0, false
	}
	v, ok := d.(detectors.Verifier)
	if !ok {
		return nil, 0, false
	}
	a := detectors.AssuranceUnknown
	if p, ok := d.(detectors.VerificationPolicy); ok {
		a = p.MaxVerificationAssurance()
	}
	return v, a, true
}

var compiled sync.Map // pattern -> *detectors.Regexp

func partnerRe(p string) *detectors.Regexp {
	if re, ok := compiled.Load(p); ok {
		return re.(*detectors.Regexp)
	}
	re := detectors.MustCompile(p)
	compiled.Store(p, re)
	return re
}

// resolve fills v with each partner's value nearest to the secret in data.
func (c *check) resolve(secret string, data []byte) (vars, error) {
	v := vars{"secret": secret}
	if len(c.partners) == 0 {
		return v, nil
	}
	at := bytes.Index(data, []byte(secret))
	names := make([]string, 0, len(c.partners))
	for n := range c.partners {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		best, dist := "", -1
		for _, m := range partnerRe(c.partners[n]).FindAllSubmatchIndex(data, -1) {
			s, e := -1, -1
			for g := 2; g+1 < len(m); g += 2 {
				if m[g] >= 0 {
					s, e = m[g], m[g+1]
					break
				}
			}
			if s < 0 {
				s, e = m[0], m[1]
			}
			val := string(data[s:e])
			if val == secret {
				continue
			}
			d := s - at
			if d < 0 {
				d = -d
			}
			if at < 0 {
				d = 0
			}
			if dist < 0 || d < dist {
				best, dist = val, d
			}
		}
		key, optional := strings.CutPrefix(n, "?")
		if best == "" {
			if optional {
				continue
			}
			return nil, fmt.Errorf("paired credential %s not found near the secret", key)
		}
		v[key] = best
	}
	return v, nil
}

func (c *check) verify(ctx context.Context, t detectors.DetectorType, ruleID, secret string, data []byte) (bool, error) {
	v, err := c.resolve(secret, data)
	if err != nil {
		return false, fmt.Errorf("%s verify: %w", ruleID, err)
	}
	switch {
	case c.base != "":
		bv, _, ok := baseVerifier(t)
		if !ok {
			return false, fmt.Errorf("%s verify: no %s verifier registered", ruleID, t)
		}
		return bv.Verify(ctx, expand(c.base, v))
	case c.http != nil:
		return c.http.do(ctx, ruleID, v)
	case c.fn != nil:
		ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
		defer cancel()
		return c.fn(ctx, v)
	}
	return false, fmt.Errorf("%s verify: no check", ruleID)
}

func (h *httpCheck) do(ctx context.Context, name string, v vars) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	raw := expand(h.URL, v)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return false, fmt.Errorf("%s verify: unusable endpoint", name)
	}
	if len(h.Hosts) > 0 && !hostAllowed(u.Hostname(), h.Hosts) {
		return false, fmt.Errorf("%s verify: endpoint host outside %v", name, h.Hosts)
	}
	var body io.Reader
	if h.Body != "" {
		body = strings.NewReader(expand(h.Body, v))
	}
	method := h.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return false, fmt.Errorf("%s verify: build request", name)
	}
	for k, val := range h.Headers {
		req.Header.Set(k, expand(val, v))
	}
	if h.ContentType != "" {
		req.Header.Set("Content-Type", h.ContentType)
	}
	status, payload, err := send(req)
	if err != nil {
		return false, fmt.Errorf("%s verify: %w", name, err)
	}
	valid := h.Valid
	if len(valid) == 0 {
		valid = []tokenverify.Rule{{Status: http.StatusOK}}
	}
	invalid := h.Invalid
	if len(invalid) == 0 {
		invalid = []tokenverify.Rule{{Status: http.StatusUnauthorized}, {Status: http.StatusForbidden}}
	}
	return tokenverify.Classify(name, status, payload, valid, invalid)
}

// send performs req and returns the status and at most 64 KiB of body.
// Errors never carry the URL or headers, which may embed the secret.
func send(req *http.Request) (int, []byte, error) {
	resp, err := verifyClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, nil, errors.New("timeout")
		}
		return 0, nil, errors.New("request failed")
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, nil, errors.New("read response")
	}
	return resp.StatusCode, payload, nil
}

func hostAllowed(host string, suffixes []string) bool {
	host = strings.ToLower(host)
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

var placeholderRe = detectors.MustCompile(`\{([a-z0-9_:'|.-]+)\}`)

func expand(tmpl string, v vars) string {
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		key := m[1 : len(m)-1]
		if rest, ok := strings.CutPrefix(key, "basic:"); ok {
			a, b, _ := strings.Cut(rest, ":")
			return base64.StdEncoding.EncodeToString([]byte(term(a, v) + ":" + term(b, v)))
		}
		name, filter, _ := strings.Cut(key, "|")
		val, ok := v[name]
		if !ok {
			return m
		}
		switch filter {
		case "url":
			return url.QueryEscape(val)
		case "b64":
			return base64.StdEncoding.EncodeToString([]byte(val))
		case "json":
			b, _ := json.Marshal(val)
			return string(b)
		}
		return val
	})
}

func term(t string, v vars) string {
	if strings.HasPrefix(t, "'") && strings.HasSuffix(t, "'") && len(t) >= 2 {
		return t[1 : len(t)-1]
	}
	return v[t]
}

// attach wires every check onto its catalog format.
func attach() {
	byID := map[string]*detectors.Format{}
	for _, h := range hostScanners {
		for _, f := range h.formats {
			byID[f.ID] = f
		}
	}
	for _, fs := range extensions {
		for _, f := range fs {
			byID[f.ID] = f
		}
	}
	for id, c := range checks {
		f := byID[id]
		if f == nil {
			panic("catalog: check for unknown rule " + id)
		}
		t := ruleType[id]
		c, id := c, id
		f.Verify = func(ctx context.Context, secret string, data []byte) (bool, error) {
			return c.verify(ctx, t, id, secret, data)
		}
		f.Assurance = c.assurance
		if c.base != "" {
			// The provider verifier's own policy is the bound, resolved at
			// verification time because provider packages may register
			// after this one. A verifier that never declared a policy
			// counts as heuristic, never as stronger evidence.
			f.AssuranceFunc = func() detectors.VerificationAssurance {
				if _, a, ok := baseVerifier(t); ok && a != detectors.AssuranceUnknown {
					return a
				}
				return detectors.AssuranceHeuristic
			}
		}
	}
}

// VerifiedRules lists the kingfisher rule ids pleno-dlp verifies through
// a catalog check (for the parity doc and its test).
func VerifiedRules() []string {
	out := make([]string, 0, len(checks))
	for id := range checks {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// CheckKind reports how rule id is verified: "base:<Type>", "http",
// "signed", or "" when the catalog does not verify it.
func CheckKind(id string) string {
	c, ok := checks[id]
	switch {
	case !ok:
		return ""
	case c.base != "":
		return "base:" + ruleType[id].String()
	case c.http != nil:
		return "http"
	}
	return "signed"
}

func (c *check) prefixOr() string {
	if c == nil {
		return ""
	}
	return c.prefix
}
