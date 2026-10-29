//go:build detector_unit

package railsmasterkey

import (
	"bytes"
	"context"
	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
	"reflect"
	"strings"
	"testing"
)

func TestFromReaderMatchesFromDataWithUnicodeWhitespace(t *testing.T) {
	data := []byte("\u2003" + "7ac21fd94b6e0c831a5f2d9e7c4b81f0" + "\u00a0")
	want, err := redactiontest.FromData(t, (Scanner{}), context.Background(), false, data)
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	got, err := redactiontest.FromReader(t, (Scanner{}), context.Background(), false, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("FromReader: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reader result differs from FromData:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestFromReaderStopsAfterProvenNonMatch(t *testing.T) {
	data := []byte("7ac21fd94b6e0c831a5f2d9e7c4b81f0x" + strings.Repeat("\u2003", 1<<20))
	got, err := redactiontest.FromReader(t, (Scanner{}), context.Background(), false, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("FromReader: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no finding, got %#v", got)
	}
}
