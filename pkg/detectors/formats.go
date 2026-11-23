package detectors

import (
	"bytes"
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Format is a supplementary, detection-only credential format attached to
// a registered DetectorType. It exists for format variants a provider's
// native detector does not match (legacy key shapes, context-anchored
// assignments, sibling credential kinds) so that coverage can grow from
// declarative data instead of hand-edited scanners. Format results carry
// the owning DetectorType and are tagged with ExtraData["format"] = ID.
// A format without Verify is detection-only (ExtraData["verification"] =
// "not-attempted"); one with Verify is verified by VerifyFormatResults
// (ExtraData["verification"] = "format").
type Format struct {
	// ID names the format (for imported rules, the upstream rule id).
	ID string
	// Keywords feed the engine's keyword prefilter (case-insensitive).
	// A format without keywords runs only when the owning detector's own
	// keywords hit.
	Keywords []string
	// Pattern is RE2. Group selects the secret: >0 picks that capture
	// group, 0 picks the first participating group, or the whole match
	// when the pattern has none.
	Pattern string
	Group   int
	// MinEntropy rejects candidates whose Shannon entropy (bits per
	// byte) is below the floor; 0 disables the gate.
	MinEntropy float64
	// Path, when set, is an RE2 the source path (file, object key, or
	// archive entry) must match; the format never fires when the caller
	// supplies no path.
	Path string
	// Verify, when set, verifies a candidate. data is the window the
	// candidate was found in, so paired credentials (a client id, a host,
	// a key id) can be resolved from nearby text. It follows the
	// Verifier contract: (false, nil) only for a provider rejection,
	// an error for anything indeterminate (including a missing partner).
	Verify func(ctx context.Context, secret string, data []byte) (bool, error)
	// Assurance is the strongest evidence a successful Verify carries; a
	// format with Verify must declare it.
	Assurance VerificationAssurance
	// AssuranceFunc, when set, supplies Assurance at verification time
	// (for formats routed to a provider verifier registered later).
	AssuranceFunc func() VerificationAssurance

	once   sync.Once
	re     *regexp.Regexp
	pathRe *regexp.Regexp
	err    error
}

// Compile compiles the pattern (and path constraint) once and reports a
// syntax error.
func (f *Format) Compile() (*regexp.Regexp, error) {
	f.once.Do(func() {
		f.re, f.err = regexp.Compile(f.Pattern)
		if f.err == nil && f.Path != "" {
			f.pathRe, f.err = regexp.Compile(f.Path)
		}
	})
	return f.re, f.err
}

var (
	formatsMu sync.RWMutex
	formats   = map[DetectorType][]*Format{}
)

// RegisterFormats attaches supplementary formats to t. The engine runs
// them after t's detector and drops candidates the detector already
// reported. Formats on a type with no registered detector never run.
func RegisterFormats(t DetectorType, fs ...*Format) {
	formatsMu.Lock()
	defer formatsMu.Unlock()
	for _, f := range fs {
		if f.ID == "" {
			panic("detectors: format without ID for type " + t.String())
		}
		for _, have := range formats[t] {
			if have.ID == f.ID {
				panic("detectors: duplicate format " + f.ID + " for type " + t.String())
			}
		}
		formats[t] = append(formats[t], f)
	}
}

// FormatsFor returns the supplementary formats registered for t.
func FormatsFor(t DetectorType) []*Format {
	formatsMu.RLock()
	defer formatsMu.RUnlock()
	return append([]*Format(nil), formats[t]...)
}

// KeywordsWithFormats returns d's keywords plus the keywords of every
// format registered for d's type, deduplicated case-insensitively.
func KeywordsWithFormats(d Detector) []string {
	base := d.Keywords()
	fs := FormatsFor(d.Type())
	if len(fs) == 0 {
		return base
	}
	seen := make(map[string]bool, len(base))
	out := make([]string, 0, len(base)+len(fs))
	for _, kw := range base {
		if !seen[strings.ToLower(kw)] {
			seen[strings.ToLower(kw)] = true
			out = append(out, kw)
		}
	}
	for _, f := range fs {
		for _, kw := range f.Keywords {
			if kw != "" && !seen[strings.ToLower(kw)] {
				seen[strings.ToLower(kw)] = true
				out = append(out, kw)
			}
		}
	}
	return out
}

// AppendFormatResults appends the matches of t's registered formats in
// data, read from path ("" when unknown), to results, skipping secrets
// already present in results.
func AppendFormatResults(t DetectorType, path string, data []byte, results []Result) []Result {
	fs := FormatsFor(t)
	if len(fs) == 0 {
		return results
	}
	return MatchFormatsAt(t, fs, path, data, results)
}

// MatchFormats is MatchFormatsAt with no source path: path-constrained
// formats do not fire.
func MatchFormats(t DetectorType, fs []*Format, data []byte, results []Result) []Result {
	return MatchFormatsAt(t, fs, "", data, results)
}

// MatchFormatsAt appends the matches of fs in data, read from path and
// typed t, to results, skipping secrets already present in results.
func MatchFormatsAt(t DetectorType, fs []*Format, path string, data []byte, results []Result) []Result {
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		seen[string(r.Raw)] = true
	}
	lower := []byte(nil)
	for _, f := range fs {
		if len(f.Keywords) > 0 {
			if lower == nil {
				lower = bytes.ToLower(data)
			}
			if !anyKeyword(lower, f.Keywords) {
				continue
			}
		}
		re, err := f.Compile()
		if err != nil {
			continue
		}
		if f.pathRe != nil && (path == "" || !f.pathRe.MatchString(path)) {
			continue
		}
		for _, m := range re.FindAllSubmatchIndex(data, -1) {
			secret := formatSecret(m, f.Group)
			if secret == nil {
				continue
			}
			raw := data[secret[0]:secret[1]]
			if len(bytes.TrimSpace(raw)) == 0 || seen[string(raw)] {
				continue
			}
			if f.MinEntropy > 0 && ShannonEntropy(string(raw)) < f.MinEntropy {
				continue
			}
			if placeholder(raw) {
				continue
			}
			seen[string(raw)] = true
			results = append(results, Result{
				DetectorType: t,
				Raw:          append([]byte(nil), raw...),
				Redacted:     redactFormat(raw),
				ExtraData: map[string]string{
					"format":       f.ID,
					"verification": "not-attempted",
				},
			})
		}
	}
	return SafeResults(results)
}

func anyKeyword(lower []byte, kws []string) bool {
	for _, kw := range kws {
		if kw != "" && bytes.Contains(lower, []byte(strings.ToLower(kw))) {
			return true
		}
	}
	return false
}

func formatSecret(m []int, group int) []int {
	if group > 0 {
		if 2*group+1 < len(m) && m[2*group] >= 0 {
			return m[2*group : 2*group+2]
		}
		return nil
	}
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 {
			return m[2*g : 2*g+2]
		}
	}
	return m[0:2]
}

var placeholderRe = regexp.MustCompile(`^(?:(?i:true|false|null|none|nil|undefined|changeme|placeholder|redacted)|(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)|\$(?:\d+|\{\d+\})|\$(?:[A-Z_]+|[a-z_]+)|\$\{(?:[A-Z_]+|[a-z_]+)\}|\{\{[ \t]*[\w ().|]+[ \t]*\}\}|<[^>]*>)$`)

// placeholder rejects template variables and obvious placeholders, the
// same allowlist shape kingfisher's imported Betterleaks filters apply.
func placeholder(raw []byte) bool {
	return placeholderRe.Match(raw)
}

func redactFormat(raw []byte) string {
	keep := 4
	if len(raw) < 12 {
		keep = len(raw) / 4
	}
	return string(raw[:keep]) + "…"
}

// VerifyFormatResults verifies, in place, every result in results that a
// format in fs with a Verify hook produced (ExtraData["format"] = its ID
// and not yet attempted). The format's declared Assurance is recorded on
// verified results; the engine does not cap it by the owning detector's
// policy because the format, not the detector, performed the check.
func VerifyFormatResults(ctx context.Context, fs []*Format, data []byte, results []Result) {
	if len(results) == 0 {
		return
	}
	byID := map[string]*Format{}
	for _, f := range fs {
		if f.Verify != nil {
			byID[f.ID] = f
		}
	}
	if len(byID) == 0 {
		return
	}
	for i := range results {
		r := &results[i]
		f := byID[r.ExtraData["format"]]
		if f == nil || r.ExtraData["verification"] != "not-attempted" {
			continue
		}
		r.Verified, r.VerificationErr = f.Verify(ctx, string(r.Raw), data)
		r.ExtraData["verification"] = "format"
		if r.Verified {
			r.VerificationAssurance = f.MaxAssurance()
		}
	}
}

// MaxAssurance is the assurance a successful Verify carries.
func (f *Format) MaxAssurance() VerificationAssurance {
	if f.AssuranceFunc != nil {
		return f.AssuranceFunc()
	}
	return f.Assurance
}

// FormatVerified reports whether r was verified by a format hook (see
// VerifyFormatResults), whose assurance the format itself declared.
func FormatVerified(r Result) bool { return r.ExtraData["verification"] == "format" }

// FormatTypes lists the types with registered formats, sorted.
func FormatTypes() []DetectorType {
	formatsMu.RLock()
	defer formatsMu.RUnlock()
	out := make([]DetectorType, 0, len(formats))
	for t := range formats {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
