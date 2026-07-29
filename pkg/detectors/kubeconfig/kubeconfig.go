// Package kubeconfig detects kubeconfig YAML containing credential
// material — `client-certificate-data:`, `client-key-data:`, or `token:`
// fields under a `users:` block.
//
// Verify probes the cluster's `/version` endpoint using the extracted
// credential and the `server:` URL from the same kubeconfig document.
//
//   - Token credentials: GET <server>/version with Authorization: Bearer <token>.
//   - Client certificate credentials: GET <server>/version using a TLS
//     client certificate constructed from the base64-decoded PEM cert+key
//     pair found in the same user block.
//
// InsecureSkipVerify=true is necessary because the cluster CA certificate
// is embedded as base64-encoded PEM in `certificate-authority-data` and
// cannot be reliably extracted for HTTP client use in all cases; the
// verification goal is authentication confirmation, not CA-chain
// validation.
//
// HTTP 200 with a Kubernetes server version JSON = Verified (the
// credential authenticates to the cluster). HTTP 401/403 = unverified
// (credential rejected). Connection errors / timeouts = unverified
// (false, nil — not a scan error).
//
// Cluster-admin scope warrants SeverityCritical. The detector emits one
// finding per credential field; Raw is the credential value, RawV2 is
// the surrounding YAML user entry name when discoverable.
//
// Because `kind: Config` is NOT exclusive to kubeconfig (kustomize, CRDs,
// and assorted tooling reuse it), a bare keyword/regex gate over-fires on
// any document that merely contains a `kind: Config` line plus an
// unrelated `token:` placeholder. To keep noise low without losing real
// findings we apply four coordinated guards:
//
//  1. Gate on BOTH a `kind: Config` line AND a kubeconfig-consistent
//     `apiVersion` line (`v1` or a `client.authentication.k8s.io/*`
//     group used by exec/auth plugins).
//  2. Require each credential field to occur within usersVicinity bytes
//     AFTER a `users:` / `user:` block marker, so credential-shaped lines
//     that live under unrelated objects are rejected.
//  3. Apply a Shannon-entropy floor on the credential value to drop
//     human-readable placeholders.
//  4. Reject obvious placeholder fills (REDACTED, changeme, example,
//     your-token-here, xxxxx-style runs) outright.
package kubeconfig

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// `v1` is the canonical kubeconfig apiVersion; the
// client.authentication.k8s.io group appears in exec-credential plugin
// stanzas embedded in real kubeconfigs.
var (
	kindRe       = regexp.MustCompile(`(?im)^\s*kind\s*:\s*Config\s*$`)
	apiVersionRe = regexp.MustCompile(`(?im)^\s*apiVersion\s*:\s*["']?(v1|client\.authentication\.k8s\.io/[^\s"']+)["']?\s*$`)
)

// usersBlockRe locates `users:` / `user:` block markers. A credential
// field only counts when it falls within usersVicinity bytes AFTER one
// of these markers — the inline vicinity check that ties the credential
// to a users block rather than an unrelated object.
var usersBlockRe = regexp.MustCompile(`(?im)^\s*-?\s*users?\s*:\s*$`)

const usersVicinity = 200

// One result per credential field. We anchor on YAML line shape (key
// indented under `user:`) and require a non-empty value.
var (
	clientCertRe = regexp.MustCompile(`(?m)^\s*client-certificate-data\s*:\s*([A-Za-z0-9+/=]{40,})\s*$`)
	clientKeyRe  = regexp.MustCompile(`(?m)^\s*client-key-data\s*:\s*([A-Za-z0-9+/=]{40,})\s*$`)
	tokenRe      = regexp.MustCompile(`(?m)^\s*token\s*:\s*([A-Za-z0-9._\-+/=]{20,})\s*$`)
	nameRe       = regexp.MustCompile(`(?m)^[\s-]*name\s*:\s*([^\s]+)\s*$`)
)

// serverRe extracts the cluster server URL from a kubeconfig YAML.
// The server: field sits under a `clusters:` block and always carries
// an https:// (or occasionally http://) URL.
var serverRe = regexp.MustCompile(`(?m)^\s*server\s*:\s*(https?://[^\s]+)`)

// verifyTimeout caps the time spent probing a single cluster endpoint.
const verifyTimeout = 5 * time.Second

// minTokenEntropy drops human-readable placeholder tokens. base64url /
// JWT material clears ~3.5 bits/char comfortably; hyphenated English
// placeholders ("your-bearer-token-here") and runs of one character do
// not. cert/key data is base64 and always clears this; we only gate the
// token field, which is the one with realistic placeholder collisions.
const minTokenEntropy = 3.5

// placeholderHints are substrings that flag a value as an obvious
// non-credential fill. Matched case-insensitively against the value.
var placeholderHints = []string{
	"redacted",
	"changeme",
	"change-me",
	"example",
	"your-token",
	"your-bearer-token",
	"placeholder",
	"replace",
	"rotate-this",
	"dummy",
	"github-actions-workflow-dispatch",
}

// maxRunLen is the longest run of a single repeated character allowed in
// a credential value. xxxxx-style manual redaction fills exceed it; real
// base64 / JWT material does not.
const maxRunLen = 8

// window represents a users-block vicinity range in the document.
type window struct{ start, end int }

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType         { return detectors.Kubeconfig }
func (Scanner) VerificationCacheUsesFullInput() bool { return true }

func (Scanner) Keywords() []string { return []string{"kind: Config", "kind:Config"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if !kindRe.Match(data) || !apiVersionRe.Match(data) {
		return nil, nil
	}

	str := string(data)

	// Compute users-block windows once: each window starts at the marker
	// and extends usersVicinity bytes. A credential field is accepted only
	// if its match start falls inside one of these windows.
	var windows []window
	for _, m := range usersBlockRe.FindAllStringIndex(str, -1) {
		windows = append(windows, window{start: m[0], end: m[0] + usersVicinity})
	}
	if len(windows) == 0 {
		return nil, nil
	}
	inUsersVicinity := func(pos int) bool {
		for _, w := range windows {
			if pos >= w.start && pos <= w.end {
				return true
			}
		}
		return false
	}

	servers := extractServers(str)

	certByPos := map[int]string{} // window-index -> base64 cert value
	keyByPos := map[int]string{}  // window-index -> base64 key value

	out := make([]detectors.Result, 0, 4)
	seen := map[string]struct{}{}

	// nearestServer returns the server URL that is closest to (and before)
	// the given position in the document, or the first server URL if all
	// servers appear after pos.
	nearestServer := func(pos int) string {
		if len(servers) == 0 {
			return ""
		}
		best := servers[0].url
		bestDist := -1
		for _, s := range servers {
			dist := pos - s.pos
			if dist >= 0 && (bestDist < 0 || dist < bestDist) {
				best = s.url
				bestDist = dist
			}
		}
		return best
	}

	// windowIndex returns the index of the users-block window that
	// contains pos, or -1 if none.
	windowIndex := func(pos int) int {
		for i, w := range windows {
			if pos >= w.start && pos <= w.end {
				return i
			}
		}
		return -1
	}

	emit := func(fieldName, value string, matchPos int) {
		if value == "" {
			return
		}
		key := fieldName + ":" + value
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		extra := map[string]string{"field": fieldName}
		// Best-effort capture of the user-name a few lines above the
		// credential field. We grab the LAST `name:` before the credential.
		if idx := strings.Index(str, value); idx > 0 {
			head := str[:idx]
			if matches := nameRe.FindAllStringSubmatch(head, -1); len(matches) > 0 {
				extra["user_name"] = matches[len(matches)-1][1]
			}
		}
		// Attach the nearest server URL.
		if srv := nearestServer(matchPos); srv != "" {
			extra["server"] = srv
		}
		res := detectors.Result{
			DetectorType: detectors.Kubeconfig,
			Raw:          []byte(value),
			Redacted:     redact(value),
			ExtraData:    extra,
			Severity:     detectors.SeverityCritical,
		}
		if userName, ok := extra["user_name"]; ok {
			res.RawV2 = []byte(userName)
		}
		out = append(out, res)
	}

	// scan applies the vicinity + value-quality guards uniformly. checkToken
	// is true only for the bearer-token field, where placeholder/entropy
	// collisions are realistic; base64 cert/key data always clears entropy
	// and we keep its guard to the vicinity + placeholder checks.
	scan := func(re *regexp.Regexp, fieldName string, checkToken bool) {
		for _, m := range re.FindAllStringSubmatchIndex(str, -1) {
			value := str[m[2]:m[3]]
			if !inUsersVicinity(m[0]) {
				continue
			}
			if isPlaceholder(value) {
				continue
			}
			if checkToken && !detectors.HasMinEntropy(value, minTokenEntropy) {
				continue
			}
			// Track cert/key positions for mTLS pairing.
			wi := windowIndex(m[0])
			switch fieldName {
			case "client-certificate-data":
				if wi >= 0 {
					certByPos[wi] = value
				}
			case "client-key-data":
				if wi >= 0 {
					keyByPos[wi] = value
				}
			}
			emit(fieldName, value, m[0])
		}
	}

	scan(clientCertRe, "client-certificate-data", false)
	scan(clientKeyRe, "client-key-data", false)
	scan(tokenRe, "token", true)

	if len(out) == 0 {
		return nil, nil
	}

	if verify {
		for i := range out {
			r := &out[i]
			srv := r.ExtraData["server"]
			if srv == "" {
				continue
			}
			field := r.ExtraData["field"]
			switch field {
			case "token":
				verified, err := verifyToken(ctx, srv, string(r.Raw))
				r.Verified = verified
				r.VerificationErr = err
			case "client-certificate-data":
				wi := findWindowIndex(str, string(r.Raw), windows)
				if wi >= 0 {
					if keyVal, ok := keyByPos[wi]; ok {
						verified, err := verifyMTLS(ctx, srv, string(r.Raw), keyVal)
						r.Verified = verified
						r.VerificationErr = err
					}
				}
			case "client-key-data":
				wi := findWindowIndex(str, string(r.Raw), windows)
				if wi >= 0 {
					if certVal, ok := certByPos[wi]; ok {
						verified, err := verifyMTLS(ctx, srv, certVal, string(r.Raw))
						r.Verified = verified
						r.VerificationErr = err
					}
				}
			}
		}
	}

	return out, nil
}

// Verify implements detectors.Verifier. The secret format is:
//
//   - Token:    "server_url|token"
//   - mTLS:    "server_url|cert_b64|key_b64"
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, "|", 3)
	switch len(parts) {
	case 2:
		// server_url|token
		return verifyToken(ctx, parts[0], parts[1])
	case 3:
		// server_url|cert_b64|key_b64
		return verifyMTLS(ctx, parts[0], parts[1], parts[2])
	default:
		return false, nil
	}
}

// serverMatch holds a server URL and its position in the document.
type serverMatch struct {
	url string
	pos int
}

// extractServers returns all cluster server URLs found in the chunk,
// preserving document order.
func extractServers(doc string) []serverMatch {
	matches := serverRe.FindAllStringSubmatchIndex(doc, -1)
	out := make([]serverMatch, 0, len(matches))
	for _, m := range matches {
		out = append(out, serverMatch{
			url: doc[m[2]:m[3]],
			pos: m[0],
		})
	}
	return out
}

// verifyToken probes GET <server>/version with a bearer token.
// HTTP 200 = verified. 401/403 = not verified. Errors = not verified.
func verifyToken(ctx context.Context, server, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	url := strings.TrimRight(server, "/") + "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{
		Timeout: verifyTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // CA cert not usable here
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Connection refused, timeout, DNS failure — not a scan error.
		return false, nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusOK, nil
}

// verifyMTLS probes GET <server>/version using a TLS client certificate
// constructed from the base64-decoded PEM cert+key pair.
func verifyMTLS(ctx context.Context, server, certB64, keyB64 string) (bool, error) {
	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return false, nil
	}
	keyPEM, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return false, nil
	}

	// Validate that the decoded bytes look like PEM. If the kubeconfig
	// stores raw DER (uncommon but possible), wrap it.
	if p, _ := pem.Decode(certPEM); p == nil {
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certPEM})
	}
	if p, _ := pem.Decode(keyPEM); p == nil {
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPEM})
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// Malformed cert/key — not a scan error, just can't verify.
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	url := strings.TrimRight(server, "/") + "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil
	}

	client := &http.Client{
		Timeout: verifyTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true, //nolint:gosec // CA cert not usable here
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusOK, nil
}

// findWindowIndex returns the index of the users-block window containing the
// given value, or -1 if none.
func findWindowIndex(doc string, value string, windows []window) int {
	if idx := strings.Index(doc, value); idx >= 0 {
		for j, w := range windows {
			if idx >= w.start && idx <= w.end {
				return j
			}
		}
	}
	return -1
}

// isPlaceholder reports whether value is an obvious non-credential fill.
func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, h := range placeholderHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	// xxxxx-style fills: any single character repeated maxRunLen+ times.
	run := 0
	var prev byte
	for i := 0; i < len(lower); i++ {
		if i > 0 && lower[i] == prev {
			run++
			if run >= maxRunLen {
				return true
			}
		} else {
			run = 1
		}
		prev = lower[i]
	}
	return false
}

func redact(t string) string {
	if len(t) <= 12 {
		return "..."
	}
	return t[:12] + "..."
}

var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
