package detectors

import (
	"bytes"
	"context"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
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
	// Prefilter, when set, is a cheap necessary condition for Pattern to
	// match: it must return true for every input the pattern matches. It
	// lets formats whose keywords cannot narrow the input (an imported
	// rule keyed on ".") skip the regexp on almost every window.
	Prefilter func(data []byte) bool

	once   sync.Once
	re     *regexp.Regexp
	pathRe *regexp.Regexp
	err    error
	// lead is the literal every match starts with (ASCII-lowercased when
	// leadFold), and anchored is ^(?:Pattern). Together they let findAll
	// try the regexp only at lead occurrences instead of every offset.
	lead     []byte
	leadFold bool
	anchored *regexp.Regexp
	// pre is the exact necessary-condition prefilter for Pattern (#984).
	pre *prefilter
	// lowerKeywords caches strings.ToLower of each non-empty keyword;
	// keywordsASCII reports that all of them are ASCII.
	lowerKeywords [][]byte
	keywordsASCII bool
}

// Compile compiles the pattern (and path constraint) once and reports a
// syntax error.
func (f *Format) Compile() (*regexp.Regexp, error) {
	f.once.Do(func() {
		f.re, f.err = regexp.Compile(f.Pattern)
		if f.err == nil {
			f.pre = buildPrefilter(f.Pattern)
		}
		if f.err == nil && f.Path != "" {
			f.pathRe, f.err = regexp.Compile(f.Path)
		}
		f.lowerKeywords = make([][]byte, 0, len(f.Keywords))
		f.keywordsASCII = true
		for _, kw := range f.Keywords {
			if kw != "" {
				f.lowerKeywords = append(f.lowerKeywords, []byte(strings.ToLower(kw)))
			}
			for i := 0; i < len(kw); i++ {
				if kw[i] >= utf8.RuneSelf {
					f.keywordsASCII = false
				}
			}
		}
		if f.err == nil {
			f.lead, f.leadFold = leadingLiteral(f.Pattern)
			if f.lead != nil {
				f.anchored, _ = regexp.Compile(`^(?:` + f.Pattern + `)`)
			}
		}
	})
	return f.re, f.err
}

// minLeadLen is the shortest leading literal worth indexing.
const minLeadLen = 3

// leadingLiteral returns the ASCII literal every match of pattern begins
// with, lowercased when the literal is case-insensitive. Imported
// Betterleaks rules all start with (?i)(?:<provider>), which Go's regexp
// cannot prefix-accelerate, so each was an NFA pass over the whole window.
func leadingLiteral(pattern string) ([]byte, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	first := re
	if re.Op == syntax.OpConcat && len(re.Sub) > 0 {
		first = re.Sub[0]
	}
	if first.Op != syntax.OpLiteral || len(first.Rune) < minLeadLen {
		return nil, false
	}
	fold := first.Flags&syntax.FoldCase != 0
	lead := make([]byte, len(first.Rune))
	for i, r := range first.Rune {
		if r >= utf8.RuneSelf {
			return nil, false
		}
		if fold && 'A' <= r && r <= 'Z' {
			r += 'a' - 'A'
		}
		lead[i] = byte(r)
	}
	return lead, fold
}

// unicodeFoldsOfASCII are the UTF-8 encodings of the only non-ASCII runes
// that case-fold to ASCII letters (U+017F ſ -> s, U+212A Kelvin -> k). A
// window containing either may match a folded literal that an ASCII
// search would miss, so it takes the plain regexp path.
var unicodeFoldsOfASCII = [][]byte{[]byte("\u017f"), []byte("\u212a")}

// findAll returns exactly re.FindAllSubmatchIndex(data, -1). When every
// match must start with a literal lead, it runs the anchored regexp only at
// lead occurrences: the leftmost match necessarily starts at the first
// occurrence where the anchored match succeeds, and leftmost-first
// semantics from a fixed start are identical anchored or not. lower lazily
// holds data lowercased in ASCII only (same length as data).
func (f *Format) findAll(data []byte, lower *asciiScratch) [][]int {
	if f.pre != nil && !f.pre.mayMatch(data) {
		return nil
	}
	if f.anchored == nil {
		return f.re.FindAllSubmatchIndex(data, -1)
	}
	hay := data
	if f.leadFold {
		for _, u := range unicodeFoldsOfASCII {
			if bytes.Contains(data, u) {
				return f.re.FindAllSubmatchIndex(data, -1)
			}
		}
		hay = lower.get(data)
	}
	var out [][]int
	for pos := 0; pos <= len(data); {
		i := bytes.Index(hay[pos:], f.lead)
		if i < 0 {
			break
		}
		k := pos + i
		m := f.anchored.FindSubmatchIndex(data[k:])
		if m == nil {
			pos = k + 1
			continue
		}
		for j := range m {
			if m[j] >= 0 {
				m[j] += k
			}
		}
		out = append(out, m)
		if m[1] > k {
			pos = m[1]
		} else {
			pos = k + 1
		}
	}
	return out
}

// asciiScratch lazily lowercases one window in ASCII into a pooled buffer;
// a fresh allocation per format-bearing detector per window (and its
// zeroing) was the largest single cost of MatchFormatsAt.
type asciiScratch struct {
	buf  *[]byte
	view []byte
	done bool
}

var asciiScratchPool = sync.Pool{New: func() any { b := make([]byte, 0, 16<<10); return &b }}

// asciiScratchKeepMax bounds the buffers returned to the pool.
const asciiScratchKeepMax = 1 << 20

func (s *asciiScratch) get(data []byte) []byte {
	if s.done {
		return s.view
	}
	if s.buf == nil {
		s.buf = asciiScratchPool.Get().(*[]byte)
	}
	dst := (*s.buf)[:0]
	if cap(dst) < len(data) {
		dst = make([]byte, 0, len(data))
	}
	dst = dst[:len(data)]
	for i, c := range data {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[i] = c
	}
	*s.buf = dst
	s.view, s.done = dst, true
	return dst
}

func (s *asciiScratch) release() {
	if s.buf != nil && cap(*s.buf) <= asciiScratchKeepMax {
		asciiScratchPool.Put(s.buf)
	}
	*s = asciiScratch{}
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
	return AppendFormatResultsLower(t, path, data, nil, results)
}

// AppendFormatResultsLower is AppendFormatResults for a caller that already
// holds asciiLower, data with only A-Z lowered (len(asciiLower) ==
// len(data)). The engine lowers each window once for its keyword prefilter;
// reusing that copy spares every format-bearing detector its own lowering
// pass (#1020). A nil asciiLower lowers on demand.
func AppendFormatResultsLower(t DetectorType, path string, data, asciiLower []byte, results []Result) []Result {
	fs := FormatsFor(t)
	if len(fs) == 0 {
		return results
	}
	return matchFormatsAt(t, fs, path, data, asciiLower, results)
}

// MatchFormats is MatchFormatsAt with no source path: path-constrained
// formats do not fire.
func MatchFormats(t DetectorType, fs []*Format, data []byte, results []Result) []Result {
	return MatchFormatsAt(t, fs, "", data, results)
}

// MatchFormatsAt appends the matches of fs in data, read from path and
// typed t, to results, skipping secrets already present in results.
func MatchFormatsAt(t DetectorType, fs []*Format, path string, data []byte, results []Result) []Result {
	return matchFormatsAt(t, fs, path, data, nil, results)
}

func matchFormatsAt(t DetectorType, fs []*Format, path string, data, asciiLowerData []byte, results []Result) []Result {
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		seen[string(r.Raw)] = true
	}
	lower := []byte(nil)
	var asciiLower asciiScratch
	if asciiLowerData != nil && len(asciiLowerData) == len(data) {
		asciiLower.view, asciiLower.done = asciiLowerData, true
	}
	defer asciiLower.release()
	for _, f := range fs {
		if _, err := f.Compile(); err != nil {
			continue
		}
		if len(f.Keywords) > 0 {
			var hay []byte
			if f.keywordsASCII {
				hay = keywordHaystack(data, &asciiLower)
			} else {
				if lower == nil {
					lower = bytes.ToLower(data)
				}
				hay = lower
			}
			if !anyLowerKeyword(hay, f.lowerKeywords) {
				continue
			}
		}
		if f.pathRe != nil && (path == "" || !f.pathRe.MatchString(path)) {
			continue
		}
		if f.Prefilter != nil && !f.Prefilter(data) {
			continue
		}
		for _, m := range f.findAll(data, &asciiLower) {
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

// unicodeLowersToASCII are the UTF-8 encodings of the only runes outside
// ASCII that unicode.ToLower maps into ASCII (U+0130 -> i, U+212A -> k).
var unicodeLowersToASCII = [][]byte{[]byte("\u0130"), []byte("\u212a")}

// keywordHaystack returns a lowercase view of data in which a lowercase
// keyword occurs exactly when it occurs in bytes.ToLower(data). Without the
// two runes above, ASCII-only lowering is equivalent for that purpose and
// avoids a Unicode re-encode of every window for every format-bearing
// detector (it was half of MatchFormatsAt's cost). The ASCII copy is shared
// with the leading-literal matcher through asciiLower.
func keywordHaystack(data []byte, lower *asciiScratch) []byte {
	for _, u := range unicodeLowersToASCII {
		if bytes.Contains(data, u) {
			return bytes.ToLower(data)
		}
	}
	return lower.get(data)
}

func anyLowerKeyword(lower []byte, kws [][]byte) bool {
	for _, kw := range kws {
		if bytes.Contains(lower, kw) {
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
