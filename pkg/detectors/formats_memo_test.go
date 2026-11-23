package detectors

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
)

// matchFormatsRef is matchFormatsAt before #1046: seen is built up front
// and every format searches its own keywords.
func matchFormatsRef(t DetectorType, fs []*Format, path string, data []byte, results []Result) []Result {
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		seen[string(r.Raw)] = true
	}
	lower := []byte(nil)
	var asciiLower asciiScratch
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
			found := false
			for _, kw := range f.lowerKeywords {
				if bytes.Contains(hay, kw) {
					found = true
					break
				}
			}
			if !found {
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
				ExtraData:    map[string]string{"format": f.ID, "verification": "not-attempted"},
			})
		}
	}
	return SafeResults(results)
}

func TestMatchFormatsMemoMatchesReference(t *testing.T) {
	fs := []*Format{
		{ID: "a", Keywords: []string{"tok_"}, Pattern: `tok_[a-z0-9]{8}`},
		{ID: "b", Keywords: []string{"TOK_", "key"}, Pattern: `(?i)key[=:]([a-z0-9]{8})`, Group: 1},
		{ID: "c", Keywords: []string{"tok_"}, Pattern: `tok_[0-9]{8}`},
		{ID: "d", Keywords: []string{"ǅkey"}, Pattern: `ǅkey[a-z]{8}`},
		{ID: "e", Pattern: `zz[0-9]{10}`},
	}
	alphabet := []string{"tok_", "TOK_", "key=", "KEY:", "ǅkey", "ǆKEY", "\u0130", "\u212a", "zz", "a", "1", "9", "x", " ", "\n"}
	r := rand.New(rand.NewSource(1046))
	for i := range 20000 {
		var b bytes.Buffer
		for range r.Intn(60) {
			b.WriteString(alphabet[r.Intn(len(alphabet))])
		}
		data := b.Bytes()
		var prior []Result
		if r.Intn(3) == 0 {
			prior = matchFormatsRef(1, fs[:1], "", data, nil)
		}
		want := matchFormatsRef(1, fs, "p.txt", data, append([]Result(nil), prior...))
		got := matchFormatsAt(1, fs, "p.txt", data, nil, append([]Result(nil), prior...))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d %q:\ngot  %+v\nwant %+v", i, data, got, want)
		}
	}
}
