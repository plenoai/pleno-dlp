package crash

import (
	"bytes"
	"context"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// detectorBudget caps the secret-detector pass so redaction cannot stall
// the crash path.
const detectorBudget = 2 * time.Second

var (
	offsetRe    = regexp.MustCompile(` \+0x[0-9a-fA-F]+`)
	hexAddrRe   = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	goroutineRe = regexp.MustCompile(`goroutine [0-9]+ \[`)
	inGorRe     = regexp.MustCompile(`in goroutine [0-9]+`)
	urlRe       = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'<>()\[\]]+`)
	emailRe     = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	ipv4Re      = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	// Three or more colon-separated hex groups, or any "::" compression,
	// distinguishes IPv6 from hh:mm:ss timestamps.
	ipv6Re = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{0,4}::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}\b`)
	// Unix and Windows absolute paths left after the known-prefix rewrite.
	// A leading "//" is a URL authority, not a path.
	unixPathRe = regexp.MustCompile(`(^|[\s"'=:(])(/[^/\s"':()][^\s"':()]*)`)
	winPathRe  = regexp.MustCompile(`\b[A-Za-z]:\\[^\s"':()]+`)
	tokenRe    = regexp.MustCompile(`[A-Za-z0-9+_=\-]{20,}`)
	hexRunRe   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// Redactor removes environment-specific and potentially sensitive content
// from crash text. The zero value applies only the pattern rules.
type Redactor struct {
	// Prefixes maps an absolute directory to the placeholder that replaces
	// it (e.g. "/Users/alice" -> "$HOME"). Longest prefix wins.
	Prefixes map[string]string
	// Detectors are run without verification over the redacted text; every
	// match is replaced with "[REDACTED:<type>]". Nil skips the pass.
	Detectors []detectors.Detector
}

// EnvPrefixes derives the placeholder map from the process environment.
func EnvPrefixes(getenv func(string) string, home string) map[string]string {
	m := map[string]string{}
	add := func(dir, ph string) {
		dir = strings.TrimRight(dir, `/\`)
		if len(dir) > 1 {
			m[dir] = ph
		}
	}
	add(home, "$HOME")
	add(getenv("GOPATH"), "$GOPATH")
	add(getenv("GOMODCACHE"), "$GOMODCACHE")
	goroot := getenv("GOROOT")
	if goroot == "" {
		// The build-time root is exactly the prefix stdlib frames carry in a
		// non-trimpath build, which is the string being redacted here.
		//lint:ignore SA1019 build-time GOROOT is the wanted value, not the host's
		goroot = runtime.GOROOT()
	}
	add(goroot, "$GOROOT")
	return m
}

// Redact applies the full pipeline: frame normalization, path rewriting,
// PII/URL/token patterns, then the secret-detector pass.
func (r *Redactor) Redact(s string) string {
	if s == "" {
		return s
	}
	s = normalizeFrames(s)
	s = redactURLs(s)
	s = moduleRelative(s)
	s = r.replacePrefixes(s)
	s = emailRe.ReplaceAllString(s, "[EMAIL]")
	s = ipv6Re.ReplaceAllString(s, "[IP]")
	s = ipv4Re.ReplaceAllString(s, "[IP]")
	s = unixPathRe.ReplaceAllStringFunc(s, redactUnixPath)
	s = winPathRe.ReplaceAllString(s, "[PATH]")
	s = tokenRe.ReplaceAllStringFunc(s, redactToken)
	return r.scrubSecrets(s)
}

// normalizeFrames drops per-run noise: PC offsets, hex arguments and
// addresses, and goroutine ids.
func normalizeFrames(s string) string {
	s = offsetRe.ReplaceAllString(s, "")
	s = hexAddrRe.ReplaceAllString(s, "0x?")
	s = goroutineRe.ReplaceAllString(s, "goroutine [")
	return inGorRe.ReplaceAllString(s, "in goroutine N")
}

// moduleRelative cuts everything before the module path on any line that
// contains it, so a non-trimpath build's checkout location never leaks.
func moduleRelative(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		j := strings.Index(l, ModulePath)
		if j <= 0 {
			continue
		}
		k := strings.LastIndexAny(l[:j], " \t\"'=(")
		lines[i] = l[:k+1] + l[j:]
	}
	return strings.Join(lines, "\n")
}

func (r *Redactor) replacePrefixes(s string) string {
	keys := make([]string, 0, len(r.Prefixes))
	for k := range r.Prefixes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, r.Prefixes[k])
	}
	return s
}

// redactURLs keeps only first-party project links recognizable.
func redactURLs(s string) string {
	return urlRe.ReplaceAllStringFunc(s, func(m string) string {
		u, err := url.Parse(m)
		if err == nil && strings.EqualFold(u.Host, "github.com") &&
			(u.Path == "/plenoai" || strings.HasPrefix(u.Path, "/plenoai/")) {
			return u.Scheme + "://github.com/plenoai"
		}
		return "[URL]"
	})
}

// redactUnixPath replaces absolute paths that were not already rewritten to
// a placeholder or module-relative form.
func redactUnixPath(m string) string {
	i := strings.IndexByte(m, '/')
	return m[:i] + "[PATH]"
}

// redactToken flags runs that look like credentials or identifiers: long
// hex, or mixed letters and digits with high entropy. Plain identifiers such
// as Go function names survive.
func redactToken(m string) string {
	if hexRunRe.MatchString(m) {
		return "[TOKEN]"
	}
	hasDigit := strings.ContainsAny(m, "0123456789")
	hasAlpha := strings.IndexFunc(m, func(c rune) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }) >= 0
	if hasDigit && hasAlpha && detectors.ShannonEntropy(m) >= 3.5 {
		return "[TOKEN]"
	}
	return m
}

// scrubSecrets runs every registered detector offline and replaces matches.
// A detector panic must not turn a crash report into a second crash.
func (r *Redactor) scrubSecrets(s string) string {
	if len(r.Detectors) == 0 {
		return s
	}
	ctx, cancel := context.WithTimeout(context.Background(), detectorBudget)
	defer cancel()
	data := []byte(s)
	lower := bytes.ToLower(data)
	for _, d := range r.Detectors {
		if ctx.Err() != nil {
			break
		}
		if !keywordHit(lower, d.Keywords()) {
			continue
		}
		results := safeFromData(ctx, d, data)
		for _, res := range results {
			ph := []byte("[REDACTED:" + res.DetectorType.String() + "]")
			for _, raw := range [][]byte{res.Raw, res.RawV2} {
				if len(raw) > 0 {
					data = bytes.ReplaceAll(data, raw, ph)
				}
			}
		}
		if len(results) > 0 {
			lower = bytes.ToLower(data)
		}
	}
	return string(data)
}

func keywordHit(lower []byte, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	for _, k := range kws {
		if bytes.Contains(lower, []byte(strings.ToLower(k))) {
			return true
		}
	}
	return false
}

func safeFromData(ctx context.Context, d detectors.Detector, data []byte) (out []detectors.Result) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	out, _ = d.FromData(ctx, false, data)
	return out
}
