// Certificate Transparency lookup for a derived public key.
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

type CTMatch struct {
	ID          int64    `json:"id"`
	CommonName  string   `json:"common_name"`
	Issuer      string   `json:"issuer_name"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	SANs        []string `json:"-"`
	NameValueIn string   `json:"name_value"`
}

type CTClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
	UserAgent  string
}

func NewCTClient() *CTClient {
	return &CTClient{
		BaseURL:   "https://crt.sh",
		Timeout:   10 * time.Second,
		UserAgent: "pleno-dlp blastradius/1.0 (+https://github.com/plenoai/pleno-dlp)",
	}
}

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

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}

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
