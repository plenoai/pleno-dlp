// Connector transport hardening.
//
// Every connector that talks to an authenticated endpoint must (a) refuse
// to send credentials over plaintext and (b) keep credentials on the
// origin they were configured for. The GitHub connector has enforced both
// rules locally for a while (validateGitHubAuthenticatedTransport and its
// origin-bound CheckRedirect); this file lifts the same guarantees into
// shared helpers so every connector gets them.
//
//   - requireSecureEndpoint rejects non-HTTPS endpoints (HTTP is still
//     allowed for loopback addresses so test servers keep working).
//   - authenticatedHTTPClient returns an *http.Client whose CheckRedirect
//     strips every credential header before following a redirect that
//     crosses a canonical-origin boundary.
//
// The redirect case matters because net/http only protects a fixed list:
// on a redirect it drops Authorization, WWW-Authenticate, and Cookie when
// the new host is not a subdomain of the original — every other header
// (PRIVATE-TOKEN, X-Api-Key, DD-API-KEY, DD-APPLICATION-KEY, Circle-Token)
// is forwarded verbatim to ANY host the endpoint 30x's to, e.g. an
// object-storage or attacker-controlled origin. Authorization is
// additionally forwarded to arbitrary subdomains of the original host.
package connectors

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// connectorCredentialHeaders names every request header a connector uses
// to carry operator credentials. On a cross-origin redirect each of these
// is deleted from the forwarded request.
var connectorCredentialHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"PRIVATE-TOKEN",
	"X-Api-Key",
	"DD-API-KEY",
	"DD-APPLICATION-KEY",
	"Circle-Token",
}

// authenticatedHTTPClient returns an HTTP client for an authenticated
// connector. Redirects that stay on the original canonical origin are
// followed untouched; redirects that cross an origin boundary are still
// followed (endpoints legitimately bounce to object storage / CDNs), but
// all credential headers are stripped first so the token can never leak
// to a third-party host.
func authenticatedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req == nil || req.URL == nil || len(via) == 0 || via[0] == nil || via[0].URL == nil {
				return nil
			}
			if canonicalOrigin(req.URL) == canonicalOrigin(via[0].URL) {
				return nil
			}
			for _, h := range connectorCredentialHeaders {
				req.Header.Del(h)
			}
			return nil
		},
	}
}

// requireSecureEndpoint validates a connector endpoint that will carry
// credentials: HTTPS is required, with HTTP permitted only for loopback
// addresses so local/test servers keep working. It mirrors the GitHub
// connector's validateGitHubAuthenticatedTransport. raw must be an
// absolute URL without embedded credentials.
func requireSecureEndpoint(provider, raw string) error {
	if raw == "" {
		return fmt.Errorf("%s: endpoint is required", provider)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s: invalid endpoint %q", provider, raw)
	}
	if u.User != nil {
		return fmt.Errorf("%s: endpoint must not embed credentials: %q", provider, raw)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
		return nil
	case u.Scheme != "http":
		return fmt.Errorf("%s: endpoint must be an HTTP(S) URL: %q", provider, raw)
	}
	return fmt.Errorf("%s: authenticated endpoint must use HTTPS (HTTP is allowed only for loopback): %q", provider, raw)
}
