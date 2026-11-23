package archive

import (
	"bytes"
	"errors"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func buildXz(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	return buf.Bytes()
}

func buildZstd(t *testing.T, data []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	defer enc.Close()
	return enc.EncodeAll(data, nil)
}

func TestLooksLikeArchive_XzZstd(t *testing.T) {
	if !LooksLikeArchive(buildXz(t, []byte("x"))) {
		t.Error("xz not detected")
	}
	if !LooksLikeArchive(buildZstd(t, []byte("x"))) {
		t.Error("zstd not detected")
	}
}

func TestWalk_StreamFormatsExpandThroughTar(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	tarBuf := buildTar(t, map[string]string{"leak.txt": akia})
	cases := map[string][]byte{
		"payload.tar.xz":  buildXz(t, tarBuf),
		"payload.tar.zst": buildZstd(t, tarBuf),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			entries, err := Walk(name, data, Limits{})
			if err != nil {
				t.Fatalf("Walk: %v", err)
			}
			if !containsAKIA(entries, akia) {
				t.Fatalf("AKIA not found: %+v", entries)
			}
		})
	}
}

func TestWalk_StreamFormatsHonorExpandedBudget(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 1<<16)
	for name, data := range map[string][]byte{"bomb.xz": buildXz(t, big), "bomb.zst": buildZstd(t, big)} {
		t.Run(name, func(t *testing.T) {
			_, err := Walk(name, data, Limits{MaxEntryBytes: 1 << 20, MaxExpandedBytes: 1024})
			var partial *PartialError
			if !errors.As(err, &partial) || partial.Kind != "max-expanded-bytes" {
				t.Fatalf("error=%v, want max-expanded-bytes", err)
			}
		})
	}
}

func TestWalk_StreamFormatsCorruptReportsGap(t *testing.T) {
	for name, data := range map[string][]byte{
		"bad.xz":  append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, bytes.Repeat([]byte{0xff}, 32)...),
		"bad.zst": append([]byte{0x28, 0xb5, 0x2f, 0xfd}, bytes.Repeat([]byte{0xff}, 32)...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Walk(name, data, Limits{})
			var partial *PartialError
			if !errors.As(err, &partial) {
				t.Fatalf("error=%v, want PartialError", err)
			}
		})
	}
}
