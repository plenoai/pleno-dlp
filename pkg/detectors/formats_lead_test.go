package detectors_test

import (
	"bytes"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/catalog"
)

// TestFormatLeadAccelerationExact pins that the leading-literal fast path
// returns exactly the plain regexp's matches for every catalog format,
// including folded case, Unicode folds, adjacent and overlapping leads.
func TestFormatLeadAccelerationExact(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	accelerated, matched := 0, 0
	var all []*detectors.Format
	for _, h := range catalog.Hosts() {
		all = append(all, h.Formats()...)
	}
	for _, fs := range catalog.Extensions() {
		all = append(all, fs...)
	}
	{
		for _, f := range all {
			re, err := f.Compile()
			if err != nil {
				continue
			}
			lead := detectors.FormatLeadForTest(f)
			if lead == "" {
				continue
			}
			accelerated++
			alphabet := "abcdefABCDEF0123456789 =:'\"\n\t._-/" + "ſK"
			for i := 0; i < 60; i++ {
				var b strings.Builder
				for j := 0; j < 1+rng.Intn(8); j++ {
					for k := 0; k < rng.Intn(40); k++ {
						b.WriteByte(alphabet[rng.Intn(len(alphabet)-6)])
					}
					l := lead
					if rng.Intn(2) == 0 {
						l = strings.ToUpper(l)
					}
					if rng.Intn(10) == 0 {
						b.WriteString("ſK")
					}
					b.WriteString(l)
					b.WriteString([]string{" = ", ": ", "=\"", " := '", "\t"}[rng.Intn(5)])
					n := 20 + rng.Intn(90)
					for k := 0; k < n; k++ {
						b.WriteByte("abcdefABCDEF0123456789"[rng.Intn(22)])
					}
					b.WriteString([]string{"\"", "'", "\n", ";", "", l}[rng.Intn(6)])
				}
				data := []byte(b.String())
				want := re.FindAllSubmatchIndex(data, -1)
				got := detectors.FormatFindAllForTest(f, data)
				if len(want) == 0 && len(got) == 0 {
					continue
				}
				matched++
				if !reflect.DeepEqual(want, got) {
					t.Fatalf("%s: fast path diverged on %q\nwant %v\ngot  %v", f.ID, data, want, got)
				}
			}
		}
	}
	if accelerated == 0 || matched == 0 {
		t.Fatalf("fast path not exercised: %d accelerated formats, %d matching inputs", accelerated, matched)
	}
	t.Logf("%d accelerated formats, %d matching inputs compared", accelerated, matched)
}

// TestKeywordHaystackMatchesUnicodeLower pins the ASCII keyword view to
// bytes.ToLower for ASCII keywords, including the runes that lower into
// ASCII.
func TestKeywordHaystackMatchesUnicodeLower(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	pieces := []string{"a", "K", "k", "I", "i", "İ", "K", "ſ", "S", "é", "É", "\xff", "_", "Key", "kEy", "sIgn"}
	kws := []string{"key", "ki", "sign", "ik", "_k", "a"}
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := 0; j < rng.Intn(12); j++ {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		data := []byte(b.String())
		uni := bytes.ToLower(data)
		hay := detectors.KeywordHaystackForTest(data)
		for _, kw := range kws {
			if bytes.Contains(uni, []byte(kw)) != bytes.Contains(hay, []byte(kw)) {
				t.Fatalf("%q kw %q: unicode=%v ascii=%v", data, kw, bytes.Contains(uni, []byte(kw)), bytes.Contains(hay, []byte(kw)))
			}
		}
	}
}
