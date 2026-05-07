// Package custom turns a JSON config file into runtime Detector objects so
// teams can add org-specific patterns ("ACME_API_KEY=…", internal token
// prefixes, license-key shapes) without forking the binary.
//
// The interpreted detector implements pkg/detectors.Detector and is fed
// through the same engine pipeline as the built-in detectors — one keyword
// prefilter per chunk, then regex match, optional Verify via HTTP GET.
//
// Config schema (JSON; one Rule per detector):
//
//	[
//	  {
//	    "name":          "ACME Internal API Key",
//	    "keywords":      ["ACME_API_KEY", "x-acme-token"],
//	    "regex":         "ACME_[A-Z0-9]{20}",
//	    "entropy_min":   3.5,
//	    "severity":      "high",
//	    "verify_url":    "https://api.acme.example/verify",
//	    "verify_header": "Authorization: Bearer {{ .Secret }}"
//	  }
//	]
//
// `keywords` are required: the engine refuses to scan a chunk that doesn't
// contain at least one keyword (case-insensitive substring match), and
// loading a rule with an empty list would force the engine to evaluate
// every chunk against the regex — a denial-of-service shape we refuse to
// configure.
//
// `verify_url` is optional. When set, a 200 response counts the secret as
// verified; 401/403 marks it explicitly unverified; transport errors
// surface as VerificationErr.
package custom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Rule is the on-disk schema. JSON instead of YAML keeps the dependency
// surface flat — a follow-up can add YAML support once we evaluate which
// parser to standardise on across the org.
type Rule struct {
	Name        string   `json:"name"`
	Keywords    []string `json:"keywords"`
	Regex       string   `json:"regex"`
	EntropyMin  float64  `json:"entropy_min,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	VerifyURL   string   `json:"verify_url,omitempty"`
	VerifyHdr   string   `json:"verify_header,omitempty"`
	HelpURI     string   `json:"help_uri,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Detector wraps a parsed Rule. Stateless after Compile — concurrent calls
// from different scan workers are safe.
type Detector struct {
	rule     Rule
	re       *regexp.Regexp
	severity detectors.Severity
	client   *http.Client
}

// Detector type used by every custom rule. We don't allocate a unique
// DetectorType per rule because the wire-stable enum can't grow at runtime;
// callers disambiguate via Result.ExtraData["custom_rule"].
const customDetectorType = detectors.GenericHighEntropy

func (d *Detector) Type() detectors.DetectorType { return customDetectorType }

func (d *Detector) Keywords() []string { return d.rule.Keywords }

func (d *Detector) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := d.re.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		secret := string(m)
		if d.rule.EntropyMin > 0 && shannonEntropy(secret) < d.rule.EntropyMin {
			continue
		}
		r := detectors.Result{
			DetectorType: customDetectorType,
			Raw:          m,
			Redacted:     redact(secret),
			Severity:     d.severity,
			ExtraData: map[string]string{
				"custom_rule": d.rule.Name,
			},
		}
		if d.rule.Description != "" {
			r.ExtraData["description"] = d.rule.Description
		}
		if verify && d.rule.VerifyURL != "" {
			ok, err := d.verify(ctx, secret)
			r.Verified = ok
			r.VerificationErr = err
		}
		out = append(out, r)
	}
	return out, nil
}

func (d *Detector) verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.rule.VerifyURL, nil)
	if err != nil {
		return false, err
	}
	if d.rule.VerifyHdr != "" {
		key, value, ok := strings.Cut(d.rule.VerifyHdr, ":")
		if !ok {
			return false, fmt.Errorf("custom rule %q: verify_header must contain ':'", d.rule.Name)
		}
		// {{ .Secret }} substitution keeps a single template token in the
		// config — full text/template would be heavier than this needs.
		req.Header.Set(strings.TrimSpace(key),
			strings.ReplaceAll(strings.TrimSpace(value), "{{ .Secret }}", secret))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("verify %q: unexpected %d", d.rule.Name, resp.StatusCode)
	}
}

// LoadFile parses a JSON file at path and returns one Detector per rule.
// Returns an aggregated error pointing at the first malformed rule so the
// CLI can surface it before any scan starts.
func LoadFile(path string) ([]*Detector, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("custom rules: open %s: %w", path, err)
	}
	defer f.Close()
	return Load(f)
}

// Load parses rules from any io.Reader. Useful for tests that build a
// fixture in memory rather than touching the filesystem.
func Load(r io.Reader) ([]*Detector, error) {
	var rules []Rule
	if err := json.NewDecoder(r).Decode(&rules); err != nil {
		return nil, fmt.Errorf("custom rules: parse: %w", err)
	}
	out := make([]*Detector, 0, len(rules))
	for i, rule := range rules {
		d, err := Compile(rule)
		if err != nil {
			return nil, fmt.Errorf("custom rules: rule[%d] %q: %w", i, rule.Name, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// Compile turns one Rule into a runtime Detector. Use this directly when
// rules originate from a non-file source (env var, secret manager, etc.).
func Compile(rule Rule) (*Detector, error) {
	if strings.TrimSpace(rule.Name) == "" {
		return nil, errors.New("name is required")
	}
	if len(rule.Keywords) == 0 {
		return nil, errors.New("at least one keyword is required (no-keyword rules force every-chunk regex evaluation)")
	}
	if rule.Regex == "" {
		return nil, errors.New("regex is required")
	}
	re, err := regexp.Compile(rule.Regex)
	if err != nil {
		return nil, fmt.Errorf("regex: %w", err)
	}
	sev, err := parseSeverity(rule.Severity)
	if err != nil {
		return nil, err
	}
	return &Detector{
		rule:     rule,
		re:       re,
		severity: sev,
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func parseSeverity(s string) (detectors.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return detectors.SeverityInfo, nil
	case "low":
		return detectors.SeverityLow, nil
	case "medium":
		return detectors.SeverityMedium, nil
	case "high":
		return detectors.SeverityHigh, nil
	case "critical":
		return detectors.SeverityCritical, nil
	default:
		return 0, fmt.Errorf("unknown severity %q (valid: info, low, medium, high, critical)", s)
	}
}

// shannonEntropy returns the Shannon entropy in bits-per-byte of s. Empty
// strings score 0; uniformly random alphanumerics over [A-Za-z0-9+/] cap
// near 6.0 bits. Threshold around 3.5 filters obvious-test values like
// "AKIA0000000000000000" without losing real keys.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, c := range s {
		freq[c]++
	}
	var h float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// redact preserves the first 4 chars of the secret and trims the rest. It
// avoids the trufflehog-style "...XXXX" suffix because most custom rule
// secrets don't have a fixed-length tail to leverage.
func redact(secret string) string {
	if len(secret) <= 4 {
		return secret
	}
	return secret[:4] + "..."
}
