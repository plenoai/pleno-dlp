//go:build detector_unit

package pgpass

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestFromReaderMatchesFromDataWithLongWhitespace(t *testing.T) {
	line := strings.Repeat(" ", 70<<10) +
		"db.internal.example.com:5432:billing:svc_billing:Tr0ub4dor&3xQ9" +
		strings.Repeat("\t", 70<<10) + "\n"
	data := []byte(line + "not a pgpass line\n" + "replica.example.com:5432:billing:svc_replica:An0ther-Secret9\n")

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
