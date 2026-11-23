package custom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Validation is a templated HTTP liveness check. Placeholders are
// `{{ .Secret }}` (the full match) and `{{ .Group.<name> }}` (a named
// capture); no other template syntax is accepted.
//
//	"validation": {
//	  "method":  "POST",
//	  "url":     "https://api.acme.example/v1/introspect?key={{ .Secret }}",
//	  "headers": {"Authorization": "Bearer {{ .Group.token }}"},
//	  "body":    "{\"token\":\"{{ .Secret }}\"}",
//	  "success_status": [200],
//	  "failure_status": [401, 403],
//	  "success_body_contains": "\"active\":true"
//	}
//
// SSRF guards (enforced, not advisory):
//   - The URL must be https and its scheme, userinfo, host and port must be
//     literal: placeholders are allowed only in the path, query and
//     fragment, so a crafted secret cannot redirect the request elsewhere.
//     Substituted URL values are percent-escaped.
//   - Every dialed address is checked after DNS resolution; loopback,
//     private, link-local (including cloud metadata 169.254.169.254),
//     CGNAT, multicast and unspecified addresses are refused unless the
//     rule sets allow_private_network (for verifying against an internal
//     service the operator controls).
//   - Redirects are never followed and response bodies are capped.
type Validation struct {
	Method              string            `json:"method,omitempty"`
	URL                 string            `json:"url"`
	Headers             map[string]string `json:"headers,omitempty"`
	Body                string            `json:"body,omitempty"`
	SuccessStatus       []int             `json:"success_status,omitempty"`
	FailureStatus       []int             `json:"failure_status,omitempty"`
	SuccessBodyContains string            `json:"success_body_contains,omitempty"`
	AllowPrivateNetwork bool              `json:"allow_private_network,omitempty"`
}

const maxValidationBody = 64 << 10

var placeholderRe = regexp.MustCompile(`\{\{\s*\.(Secret|Group\.([A-Za-z_][A-Za-z0-9_]*))\s*\}\}`)

type validator struct {
	cfg    Validation
	method string
	client *http.Client
}

func compileValidation(v *Validation, re *regexp.Regexp) (*validator, error) {
	if v == nil {
		return nil, nil
	}
	method := strings.ToUpper(strings.TrimSpace(v.Method))
	switch method {
	case "":
		method = http.MethodGet
	case http.MethodGet, http.MethodPost, http.MethodHead, http.MethodPut:
	default:
		return nil, fmt.Errorf("validation.method %q not allowed (GET, POST, HEAD, PUT)", v.Method)
	}
	check := func(field, s string) error {
		for _, sub := range placeholderRe.FindAllStringSubmatch(s, -1) {
			if sub[2] != "" && re.SubexpIndex(sub[2]) < 0 {
				return fmt.Errorf("validation.%s references unknown capture group %q", field, sub[2])
			}
		}
		rest := placeholderRe.ReplaceAllString(s, "")
		if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
			return fmt.Errorf("validation.%s: only {{ .Secret }} and {{ .Group.<name> }} placeholders are supported", field)
		}
		return nil
	}
	if strings.TrimSpace(v.URL) == "" {
		return nil, errors.New("validation.url is required")
	}
	if err := check("url", v.URL); err != nil {
		return nil, err
	}
	// Parse with placeholders blanked to inspect the literal authority.
	u, err := url.Parse(placeholderRe.ReplaceAllString(v.URL, "x"))
	if err != nil {
		return nil, fmt.Errorf("validation.url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("validation.url must use https")
	}
	if u.Host == "" {
		return nil, errors.New("validation.url must have a host")
	}
	if authorityHasPlaceholder(v.URL) {
		return nil, errors.New("validation.url: placeholders are not allowed in the scheme, userinfo, host or port")
	}
	for k, val := range v.Headers {
		if placeholderRe.MatchString(k) || strings.Contains(k, "{{") {
			return nil, fmt.Errorf("validation.headers: placeholders are not allowed in header names (%q)", k)
		}
		if strings.EqualFold(k, "Host") {
			return nil, errors.New("validation.headers: Host cannot be overridden")
		}
		if err := check("headers."+k, val); err != nil {
			return nil, err
		}
	}
	if err := check("body", v.Body); err != nil {
		return nil, err
	}
	if len(v.SuccessStatus) == 0 && v.SuccessBodyContains == "" {
		v.SuccessStatus = []int{http.StatusOK}
	}
	if len(v.FailureStatus) == 0 {
		v.FailureStatus = []int{http.StatusUnauthorized, http.StatusForbidden}
	}
	return &validator{cfg: *v, method: method, client: guardedClient(v.AllowPrivateNetwork)}, nil
}

// authorityHasPlaceholder reports whether a placeholder appears before the
// first '/', '?' or '#' after "scheme://".
func authorityHasPlaceholder(raw string) bool {
	i := strings.Index(raw, "://")
	if i < 0 {
		return strings.Contains(raw, "{{")
	}
	if strings.Contains(raw[:i], "{{") {
		return true
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return strings.Contains(rest, "{{")
}

func render(tmpl string, secret string, groups map[string]string, escape func(string) string) string {
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		sub := placeholderRe.FindStringSubmatch(m)
		v := secret
		if sub[2] != "" {
			v = groups[sub[2]]
		}
		if escape != nil {
			return escape(v)
		}
		return v
	})
}

func (v *validator) validate(ctx context.Context, secret string, groups map[string]string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var body io.Reader
	if v.cfg.Body != "" {
		body = strings.NewReader(render(v.cfg.Body, secret, groups, nil))
	}
	req, err := http.NewRequestWithContext(ctx, v.method, render(v.cfg.URL, secret, groups, url.QueryEscape), body)
	if err != nil {
		return false, err
	}
	for k, val := range v.cfg.Headers {
		hv := render(val, secret, groups, nil)
		if strings.ContainsAny(hv, "\r\n") {
			return false, errors.New("validation: header value contains CR/LF")
		}
		req.Header.Set(k, hv)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxValidationBody))
	for _, c := range v.cfg.FailureStatus {
		if resp.StatusCode == c {
			return false, nil
		}
	}
	statusOK := len(v.cfg.SuccessStatus) == 0
	for _, c := range v.cfg.SuccessStatus {
		if resp.StatusCode == c {
			statusOK = true
		}
	}
	if statusOK && (v.cfg.SuccessBodyContains == "" || strings.Contains(string(respBody), v.cfg.SuccessBodyContains)) {
		return true, nil
	}
	if statusOK {
		return false, nil // status matched but body proved inactive
	}
	return false, fmt.Errorf("validation: unexpected status %d", resp.StatusCode)
}

// guardedClient returns an HTTP client that never follows redirects and,
// unless allowPrivate, refuses to connect to non-public addresses. The
// check runs in Dialer.Control on the resolved IP, so DNS rebinding cannot
// bypass it.
func guardedClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !publicIP(ip) {
				return fmt.Errorf("validation: refusing to connect to non-public address %s", host)
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:                 nil, // a proxy would hide the dialed address from the guard
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func publicIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		if cgnat.Contains(ip) || ip[0] == 0 {
			return false
		}
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified())
}
