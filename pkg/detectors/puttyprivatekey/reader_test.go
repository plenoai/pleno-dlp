//go:build detector_unit

package puttyprivatekey

import (
	"bytes"
	"context"
	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
	"reflect"
	"strings"
	"testing"
)

func TestFromReaderMatchesFromDataAcrossLargeBoundary(t *testing.T) {
	prefix := "preamble\n"
	padding := strings.Repeat("x", (32<<10)-len(prefix)-4)
	data := []byte(prefix + padding + "tai" + syntheticUnencrypted + "\nepilogue")
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
