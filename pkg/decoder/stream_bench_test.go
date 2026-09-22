package decoder

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func BenchmarkWalkVariantsSparse(b *testing.B) {
	for name, data := range map[string][]byte{
		"plain": bytes.Repeat([]byte("healthy log record\n"), 1024),
		"utf16": append([]byte{0xff, 0xfe}, bytes.Repeat([]byte{'a', 0}, 16*1024)...),
	} {
		b.Run(name, func(b *testing.B) {
			reader := bytes.NewReader(data)
			b.ReportAllocs()
			for b.Loop() {
				if err := WalkVariants(context.Background(), reader, int64(len(data)), func(string, io.ReaderAt, int64) error { return nil }); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
