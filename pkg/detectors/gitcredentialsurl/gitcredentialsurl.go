// Package gitcredentialsurl detects `scheme://user:pass@host` credential
// lines of the kind git's credential.helper=store writes to
// `.git-credentials` — one bare URL per line, userinfo unescaped.
//
// This is deliberately a *complementary* detector to
// pkg/detectors/basicauth, not a duplicate of it. basicauth already
// covers the well-formed case (`https://user:pass@host` where
// net/url.Parse round-trips cleanly) via its own regex + entropy +
// placeholder gates. What basicauth's net/url-based pipeline cannot
// handle is userinfo containing raw RFC 3986 reserved characters —
// `#` in particular starts a URL fragment, and a stray `@` inside the
// password shifts where the authority/userinfo boundary falls. git's
// credential-store format writes these characters unescaped (it is a
// plain key=value-ish text file, not a browser-facing URL), so a
// leaked `.git-credentials` line with `#`, an extra `@`, or other
// reserved punctuation in the password silently fails net/url.Parse
// and basicauth drops the finding entirely — see the docstring on
// basicAuthWouldCatch below for the exact deferral rule.
//
// Because this shape has no keyword literal that reliably appears in
// content (basicauth already claims "://" via its own Keywords()), this
// detector implements detectors.FullChunkDetector.
//
// Verify is deliberately not implemented (class b), same rationale as
// basicauth: the host is data-controlled and arbitrary.
package gitcredentialsurl

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// lineRe matches one bare scheme://... URL occupying an entire line
// (git-credentials convention: one credential per line, no
// surrounding text). \S+ forbids embedded whitespace.
var lineRe = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`(?m)^[ \t]*((?:https?|ftp)://\S+)[ \t]*$`) })

var placeholders = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pass":          {},
	"pwd":           {},
	"secret":        {},
	"changeme":      {},
	"example":       {},
	"placeholder":   {},
	"your_password": {},
	"yourpassword":  {},
	"xxx":           {},
	"x-oauth-basic": {},
	"token":         {},
	"credentials":   {},
	"admin":         {},
	"test":          {},
	"":              {},
}

func isPlaceholder(s string) bool {
	_, ok := placeholders[strings.ToLower(s)]
	return ok
}

// templatingDelims mirrors basicauth's gate: ${VAR}, {{var}}, <password>.
const templatingDelims = "{}<>$%"

func hasTemplatingDelim(s string) bool {
	return strings.ContainsAny(s, templatingDelims)
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitCredentialsURL }

// Keywords is documentation-only — see the package doc comment for why
// this detector opts into WantsFullChunk instead.
func (Scanner) Keywords() []string { return []string{"://"} }

func (Scanner) WantsFullChunk() bool { return true }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if !bytes.Contains(data, []byte("://")) {
		return nil, nil
	}
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for start := 0; start < len(str); {
		line := str[start:]
		if end := strings.IndexByte(line, '\n'); end >= 0 {
			line = line[:end]
			start += end + 1
		} else {
			start = len(str)
		}
		scanLine([]byte(line), seen, &out)
	}

	return out, nil
}

// FromReader keeps the regexp grammar and line anchors of FromData while the
// replay helper skips invalid arbitrarily long lines without retaining them.
func (s Scanner) FromReader(ctx context.Context, _ bool, r io.ReaderAt, size int64) ([]detectors.Result, error) {
	seen := map[string]struct{}{}
	var out []detectors.Result
	err := detectors.ForEachReaderLineSubmatch(ctx, r, size, lineRe(), []byte("://"), 1, 0, []int{1}, func(match [][]byte) error {
		scanMatch(match, seen, &out)
		return nil
	})
	return out, err
}

func scanLine(line []byte, seen map[string]struct{}, out *[]detectors.Result) {
	m := lineRe().FindStringSubmatch(string(line))
	if len(m) < 2 {
		return
	}
	appendMatch(m[1], seen, out)
}

func scanMatch(match [][]byte, seen map[string]struct{}, out *[]detectors.Result) {
	if len(match) < 1 {
		return
	}
	appendMatch(string(match[0]), seen, out)
}

func appendMatch(uri string, seen map[string]struct{}, out *[]detectors.Result) {
	if basicAuthWouldCatch(uri) {
		// Already basicauth's job; skip to avoid a duplicate
		// finding under a second DetectorType.
		return
	}
	user, pass, host, ok := splitUserinfo(uri)
	if !ok {
		return
	}
	if user == "" || pass == "" {
		return
	}
	if hasTemplatingDelim(user) || hasTemplatingDelim(pass) {
		return
	}
	if isPlaceholder(user) || isPlaceholder(pass) {
		return
	}
	key := uri
	if _, dup := seen[key]; dup {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, detectors.Result{
		DetectorType: detectors.GitCredentialsURL,
		Raw:          []byte(pass),
		RawV2:        []byte(uri),
		Redacted:     redact(pass),
		ExtraData: map[string]string{
			"user": user,
			"host": host,
		},
		Severity: detectors.SeverityHigh,
	})
}

// basicAuthWouldCatch reports whether net/url.Parse cleanly recovers a
// non-empty username and password from uri. When it does, basicauth's
// own regex + net/url pipeline already covers this line and this
// detector defers rather than double-report. When Parse fails, or
// silently truncates the credential at an unescaped `#`/`@`, this
// returns false and the caller falls through to the manual,
// non-net/url split below.
func basicAuthWouldCatch(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.User == nil {
		return false
	}
	user := u.User.Username()
	pass, set := u.User.Password()
	return user != "" && set && pass != ""
}

// splitUserinfo recovers (user, password, host) from a raw
// `scheme://userinfo@host[/path]` string without net/url, so unescaped
// RFC 3986 reserved characters in the password (#, extra @) do not
// truncate or misparse it. Per RFC 3986 §3.2, the host boundary is the
// *last* unescaped `@` in the authority component; userinfo itself
// splits on the *first* `:` into user/password.
func splitUserinfo(uri string) (user, pass, host string, ok bool) {
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return "", "", "", false
	}
	rest := uri[idx+3:]
	lastAt := strings.LastIndex(rest, "@")
	if lastAt < 0 {
		return "", "", "", false
	}
	authority := rest[:lastAt]
	hostAndPath := rest[lastAt+1:]
	if hostAndPath == "" {
		return "", "", "", false
	}
	if slash := strings.IndexByte(hostAndPath, '/'); slash >= 0 {
		host = hostAndPath[:slash]
	} else {
		host = hostAndPath
	}
	if host == "" || strings.ContainsAny(host, " \t@") {
		return "", "", "", false
	}
	colon := strings.Index(authority, ":")
	if colon < 0 {
		return "", "", "", false
	}
	user = authority[:colon]
	pass = authority[colon+1:]
	if user == "" || pass == "" {
		return "", "", "", false
	}
	return user, pass, host, true
}

func redact(s string) string {
	if len(s) <= 4 {
		return "..."
	}
	return s[:2] + "..."
}

func init() {
	detectors.Register(Scanner{})
}

var _ detectors.ReaderDetector = Scanner{}
