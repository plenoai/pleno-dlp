package decoder

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"reflect"
	"strings"
	"testing"
)

type countedRunReader struct {
	io.ReaderAt
	calls int
}

func (r *countedRunReader) ReadAt(p []byte, offset int64) (int, error) {
	r.calls++
	return r.ReaderAt.ReadAt(p, offset)
}

func TestWalkVariantsCoalescesLargeRunReads(t *testing.T) {
	body := bytes.Repeat([]byte("printable log record\n"), 8000)
	for source, encoded := range map[string]string{
		"base64": base64.StdEncoding.EncodeToString(body),
		"hex":    hex.EncodeToString(body),
	} {
		r := &countedRunReader{ReaderAt: strings.NewReader(encoded)}
		found := false
		err := WalkVariants(context.Background(), r, int64(len(encoded)), func(name string, reader io.ReaderAt, size int64) error {
			if name == source {
				found = true
				if size != int64(len(body)) {
					t.Fatalf("%s decoded size = %d, want %d", source, size, len(body))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatalf("%s variant is missing", source)
		}
		if r.calls > len(encoded)/4096+32 {
			t.Fatalf("%s: %d reads for %d bytes; decoder reads were not coalesced", source, r.calls, len(encoded))
		}
	}
}

func TestWalkVariantsMatchesBuffered(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	secret := []byte("ghp_" + strings.Repeat("abcDEF012", 4))
	encoded := base64.StdEncoding.EncodeToString(secret)
	inputs := [][]byte{
		nil,
		[]byte("plain text"),
		[]byte(encoded),
		[]byte("x " + encoded + " = " + encoded),
		[]byte(hex.EncodeToString(secret)),
		[]byte("%67%68%70_" + strings.Repeat("abcDEF012", 4) + "+%ZZ%"),
		[]byte(`\u0067\u0068\u0070_hello\uD800\uDC00\uFFFF\uZZZZ`),
		append([]byte{0xff, 0xfe}, bytes.Repeat([]byte{'a', 0}, 64)...),
		append([]byte{0xfe, 0xff}, bytes.Repeat([]byte{0, 'a'}, 64)...),
		bytes.Repeat([]byte{'a'}, 128*1024),
		[]byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("secret printable text "), 8000))),
	}
	borderline := append(bytes.Repeat([]byte("a"), 20), make([]byte, 6)...)
	inputs = append(inputs, []byte(strings.Repeat(base64.StdEncoding.EncodeToString(borderline)+" ", 3)))
	for padding := 0; padding < 5; padding++ {
		for _, prefix := range []string{"", "_", "+", "_-", "/+", "a", "ab", "abc"} {
			inputs = append(inputs, []byte(prefix+strings.TrimRight(encoded, "=")+strings.Repeat("=", padding)))
		}
	}
	for offset := 65524; offset < 65540; offset++ {
		for _, tail := range []string{encoded, "%67%68%70_hello", `\u0067\u0068\u0070_hello`, hex.EncodeToString(secret)} {
			inputs = append(inputs, []byte(strings.Repeat(" ", offset)+tail))
		}
	}
	rng := rand.New(rand.NewPCG(123, 456))
	for i := 0; i < 500; i++ {
		var b bytes.Buffer
		for j := 0; j < 1+rng.IntN(12); j++ {
			data := make([]byte, rng.IntN(100))
			for k := range data {
				data[k] = byte(rng.IntN(256))
				if rng.IntN(5) != 0 {
					data[k] = byte(32 + rng.IntN(95))
				}
			}
			switch rng.IntN(4) {
			case 0:
				b.WriteString(base64.StdEncoding.EncodeToString(data))
			case 1:
				b.WriteString(base64.RawURLEncoding.EncodeToString(data))
			case 2:
				b.WriteString(hex.EncodeToString(data))
			default:
				b.Write(data)
			}
			b.WriteByte(' ')
		}
		inputs = append(inputs, b.Bytes())
	}
	for i, data := range inputs {
		var got []Variant
		err := WalkVariants(context.Background(), bytes.NewReader(data), int64(len(data)), func(source string, r io.ReaderAt, size int64) error {
			body, err := io.ReadAll(io.NewSectionReader(r, 0, size))
			if len(body) == 0 && data == nil {
				body = nil
			}
			got = append(got, Variant{source, body})
			return err
		})
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if want := Variants(data); !reflect.DeepEqual(got, want) {
			if len(got) != len(want) {
				t.Fatalf("case %d: got %d variants; want %d", i, len(got), len(want))
			}
			for j := range want {
				if got[j].Source != want[j].Source || !bytes.Equal(got[j].Data, want[j].Data) {
					t.Fatalf("case %d: variant %d (%s) differs: got %d bytes; want %d", i, j, want[j].Source, len(got[j].Data), len(want[j].Data))
				}
			}
		}
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary output leaked: %v, %v", entries, err)
	}
}

func TestWalkVariantsCleanupAndErrors(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	input := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("secret "), 20)))
	wantErr := errors.New("callback failed")
	err := WalkVariants(context.Background(), bytes.NewReader(input), int64(len(input)), func(source string, reader io.ReaderAt, size int64) error {
		if source == "" {
			return nil
		}
		f, ok := reader.(*os.File)
		if !ok {
			t.Fatal("decoded variant is not file backed")
		}
		info, err := f.Stat()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe temporary permissions: %v, %v", info, err)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("callback error lost: %v", err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary output leaked on error: %v, %v", entries, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WalkVariants(ctx, bytes.NewReader(input), int64(len(input)), func(string, io.ReaderAt, int64) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	// A truncated source must be a coverage error, not an invalid encoded run.
	if err := WalkVariants(context.Background(), bytes.NewReader(input), int64(len(input)+1), func(string, io.ReaderAt, int64) error { return nil }); err == nil {
		t.Fatal("short source silently accepted")
	}
}
