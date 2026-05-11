// Certificate Transparency lookup for a derived public key.
//
// crt.sh indexes every CT-logged certificate (effectively, every public
// TLS cert issued after 2018) and exposes a JSON endpoint that returns
// every certificate whose Subject Public Key Info SHA-256 matches a
// given hex digest. We hit that endpoint with the fingerprint produced
// by Derive() and surface the distinct domains the key signs.
//
// Privacy: only the SHA-256 of the SPKI leaves the host. The private
// key and the certificate body stay local. The fingerprint is itself
// a public value — it appears in every certificate the key has ever
// signed and in the CT log itself. There is no exfiltration risk
// distinct from the original certificate being already public.
//
// Coverage gaps the caller must understand: CT enforcement began ~2018,
// internal CAs and self-signed certs typically do not appear, and a
// "no match" answer therefore does not prove the key is unused — it
// proves the key is not in a CT-logged TLS chain. The Lookup
// implementation surfaces this distinction by returning ([]CTMatch{},
// nil) for "no match" and a typed error only for transport failures,
// so callers can render "no CT-logged certs" rather than "untracked
// key".
package blastradius

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CTMatch is a single certificate row returned by crt.sh.
type CTMatch struct {
	ID          int64    `json:"id"`
	CommonName  string   `json:"common_name"`
	Issuer      string   `json:"issuer_name"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	SANs        []string `json:"-"`
	NameValueIn string   `json:"name_value"`
}

// CTClient queries Certificate Transparency for a given SPKI fingerprint.
// Tests inject a custom HTTPClient that points at an httptest.Server.
type CTClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
	UserAgent  string
}

// NewCTClient returns a CTClient pointed at crt.sh with conservative
// defaults: 10s request timeout, identifying UA. crt.sh has no
// authenticated tier — the timeout is the only knob.
func NewCTClient() *CTClient {
	return &CTClient{
		BaseURL:   "https://crt.sh",
		Timeout:   10 * time.Second,
		UserAgent: "pleno-dlp blastradius/1.0 (+https://github.com/plenoai/pleno-dlp)",
	}
}

// Lookup queries CT logs for certificates whose SPKI SHA-256 matches
// the supplied hex fingerprint. Returns the deduplicated set of matches
// sorted by CT log ID. A nil slice with nil error means "no cert found
// in any CT log" — distinct from a transport failure, which returns
// nil + typed error.
func (c *CTClient) Lookup(ctx context.Context, spkiSHA256Hex string) ([]CTMatch, error) {
	if !isHex64(spkiSHA256Hex) {
		return nil, fmt.Errorf("blastradius: invalid SPKI sha256 hex %q", spkiSHA256Hex)
	}
	q := url.Values{}
	q.Set("spkisha256", spkiSHA256Hex)
	q.Set("output", "json")
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	req.Header.Set("Accept", "application/json")

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("blastradius: crt.sh status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw []CTMatch
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("blastradius: decode crt.sh: %w", err)
	}
	for i := range raw {
		raw[i].SANs = splitSANs(raw[i].NameValueIn)
	}
	sort.SliceStable(raw, func(i, j int) bool { return raw[i].ID < raw[j].ID })
	return raw, nil
}

// Domains returns the deduplicated set of Subject CN + SAN values
// across the supplied matches. Used to assemble the
// "blast_radius_domains" finding metadata.
func Domains(matches []CTMatch) []string {
	seen := make(map[string]struct{})
	for _, m := range matches {
		if m.CommonName != "" {
			seen[normalizeDomain(m.CommonName)] = struct{}{}
		}
		for _, san := range m.SANs {
			seen[normalizeDomain(san)] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		if d == "" {
			continue
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// splitSANs normalises the crt.sh `name_value` field (a newline-
// delimited string) into a clean slice. Wildcards (`*.example.com`)
// and punycode are preserved verbatim because they carry blast-radius
// meaning.
func splitSANs(nameValue string) []string {
	if nameValue == "" {
		return nil
	}
	parts := strings.Split(nameValue, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// normalizeDomain lower-cases and trims a domain.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}

// isHex64 validates that s is exactly 64 lowercase hex characters —
// the shape of a SHA-256 digest. Used as a pre-flight check so we do
// not send malformed queries that crt.sh would reject with HTML.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
