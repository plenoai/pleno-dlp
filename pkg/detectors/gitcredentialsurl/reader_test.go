//go:build detector_unit

package gitcredentialsurl

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestFromReaderMatchesFromDataWithDuplicateAndLongInvalidLine(t *testing.T) {
	valid := "https://ops@example.com:Qx7!#Zeta9@github.example.com"
	splitMarker := strings.Repeat(" ", (32<<10)-len("https")-1) + "https://ops@example.com:Qx7!#Zeta9@github.example.com\n"
	data := []byte(splitMarker +
		valid + "\n" +
		strings.Repeat("x", 100<<10) + "\n" +
		"\u3000" + valid + "\u3000\n" +
		valid + "\n")

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
