package volumeset

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/archive"
)

func TestJobsSpannedZip(t *testing.T) {
	s := New[int]()
	for _, k := range []string{"a.zip", "a.z02", "a.z01", "lone.zip", "b.z01", "c.zip.001", "c.zip.002"} {
		if !s.Add(k, 10, 0) {
			t.Fatalf("%s not a volume", k)
		}
	}
	if s.Add("notes.txt", 1, 0) {
		t.Fatal("notes.txt is not a volume")
	}
	got := map[string][]string{}
	for _, j := range s.Jobs(1 << 20) {
		var ks []string
		for _, m := range j.All() {
			ks = append(ks, m.Key)
		}
		got[j.Head.Key] = ks
		if j.Head.Key == "a.z01" && j.Scheme != archive.VolumeZipSpan {
			t.Fatalf("scheme %v", j.Scheme)
		}
	}
	want := map[string][]string{
		"a.z01":     {"a.z01", "a.z02", "a.zip"},
		"lone.zip":  {"lone.zip"},
		"b.z01":     {"b.z01"}, // no terminal: not joinable
		"c.zip.001": {"c.zip.001", "c.zip.002"},
	}
	if len(got) != len(want) {
		t.Fatalf("jobs %v", got)
	}
	for k, w := range want {
		g := got[k]
		if len(g) != len(w) {
			t.Fatalf("%s: %v", k, g)
		}
		for i := range w {
			if g[i] != w[i] {
				t.Fatalf("%s: %v", k, g)
			}
		}
	}
}
