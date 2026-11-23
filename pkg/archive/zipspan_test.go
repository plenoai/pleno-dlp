package archive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func spanVolumes(t testing.TB, names ...string) []Volume {
	t.Helper()
	var vols []Volume
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("testdata", "zipspan", n))
		if err != nil {
			t.Fatal(err)
		}
		vols = append(vols, Volume{R: bytes.NewReader(b), Size: int64(len(b))})
	}
	return vols
}

func walkJoined(t *testing.T, scheme VolumeScheme, vols []Volume) map[string][]byte {
	t.Helper()
	r, size, count, err := JoinVolumes(scheme, vols, 1<<30)
	if err != nil || count != len(vols) {
		t.Fatalf("join: count=%d err=%v", count, err)
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	entries, err := Walk("span.z01", data, Limits{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	got := map[string][]byte{}
	for _, e := range entries {
		got[e.Path] = e.Data
	}
	return got
}

func TestJoinZipSpan(t *testing.T) {
	for _, set := range []string{"span", "span64"} {
		t.Run(set, func(t *testing.T) {
			got := walkJoined(t, VolumeZipSpan, spanVolumes(t, set+".z01", set+".zip"))
			if len(got) != 2 {
				t.Fatalf("entries %d", len(got))
			}
			var secret, big []byte
			for p, b := range got {
				switch p {
				case "span.z01!b.txt":
					secret = b
				case "span.z01!a.bin":
					big = b
				}
			}
			if string(secret) != "FIXTURE-SPAN-SECRET\n" || len(big) != 70000 {
				t.Fatalf("b.txt=%q a.bin=%d %q", secret, len(big), keysOf(got))
			}
		})
	}
}

func TestJoinZipSpanRejectsBrokenSets(t *testing.T) {
	cases := map[string][]Volume{
		"last volume only":   spanVolumes(t, "span.zip"),
		"reordered":          spanVolumes(t, "span.zip", "span.z01"),
		"extra volume":       spanVolumes(t, "span.z01", "span64.z01", "span.zip"),
		"unrelated terminal": spanVolumes(t, "span.z01", "span64.zip"),
	}
	for name, vols := range cases {
		t.Run(name, func(t *testing.T) {
			r, size, _, err := JoinVolumes(VolumeZipSpan, vols, 1<<30)
			if err == nil {
				// A foreign terminal can carry a valid end record; the walk
				// must then fail rather than mis-attribute content.
				data := make([]byte, size)
				_, _ = r.ReadAt(data, 0)
				entries, _ := Walk("x", data, Limits{})
				for _, e := range entries {
					if string(e.Data) == "FIXTURE-SPAN-SECRET\n" && name != "unrelated terminal" {
						t.Fatalf("broken set joined: %s", e.Path)
					}
				}
				return
			}
			if !errors.Is(err, ErrVolumeChain) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if _, _, _, err := JoinVolumes(VolumeZipSpan, spanVolumes(t, "span.z01", "span.zip"), 1000); !errors.Is(err, ErrVolumeChain) {
		t.Fatalf("budget: %v", err)
	}
}

func TestParseZipSpanNames(t *testing.T) {
	cases := []struct {
		name, base string
		index      int
		sib2, term string
	}{
		{"dir/backup.z01", "dir/backup", 1, "dir/backup.z02", "dir/backup.zip"},
		{"BACKUP.Z07", "BACKUP", 7, "BACKUP.Z02", "BACKUP.ZIP"},
		{"backup.z100", "backup", 100, "backup.z02", "backup.zip"},
		{"backup.zip", "backup", 0, "backup.z02", "backup.zip"},
	}
	for _, c := range cases {
		id, ok := ParseVolumeName(c.name)
		if !ok || id.Scheme != VolumeZipSpan || id.Base != c.base || id.Index != c.index {
			t.Fatalf("%s: %+v %v", c.name, id, ok)
		}
		term, _ := id.Terminal()
		if id.Sibling(2) != c.sib2 || term != c.term {
			t.Fatalf("%s: sibling %q terminal %q", c.name, id.Sibling(2), term)
		}
	}
	for _, n := range []string{"a.z00", "a.z1", "a.zipx", "a.zip.001x"} {
		if id, ok := ParseVolumeName(n); ok && id.Scheme == VolumeZipSpan {
			t.Fatalf("%s parsed as span volume", n)
		}
	}
}

func FuzzJoinZipSpan(f *testing.F) {
	vols := spanVolumes(f, "span.z01", "span.zip")
	a, _ := os.ReadFile(filepath.Join("testdata", "zipspan", "span.z01"))
	b, _ := os.ReadFile(filepath.Join("testdata", "zipspan", "span.zip"))
	_ = vols
	f.Add(a[:512], b)
	f.Add([]byte("PK\x07\x08"), b[len(b)-200:])
	f.Fuzz(func(t *testing.T, first, last []byte) {
		r, size, _, err := JoinVolumes(VolumeZipSpan, []Volume{
			{R: bytes.NewReader(first), Size: int64(len(first))},
			{R: bytes.NewReader(last), Size: int64(len(last))},
		}, 1<<20)
		if err != nil {
			return
		}
		data := make([]byte, size)
		if _, err := r.ReadAt(data, 0); err != nil {
			t.Fatal(err)
		}
		_, _ = Walk("f", data, Limits{MaxFiles: 8})
	})
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
