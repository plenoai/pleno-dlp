//go:build detector_unit

package privatekey

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestFromReaderMatchesFromDataAcrossLargeBoundary(t *testing.T) {
	prefix := "preamble\n"
	padding := strings.Repeat("x", (32<<10)-len(prefix)-4)
	data := []byte(prefix + padding + "tai" + rsaBlock + "\n" + pgpBlock + "\nepilogue")
	want, err := (Scanner{}).FromData(context.Background(), false, data)
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	got, err := (Scanner{}).FromReader(context.Background(), false, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("FromReader: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reader result differs from FromData:\n got: %#v\nwant: %#v", got, want)
	}
}
