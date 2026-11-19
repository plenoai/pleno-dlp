//go:build detector_unit

package azurestoragekey

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
)

var dummyKey = strings.Repeat("A", 86) + "=="

func TestFromData_ConnectionString(t *testing.T) {
	data := []byte("AccountName=examplestore AccountKey=" + dummyKey)
	res, err := redactiontest.FromData(t, Scanner{}, context.Background(), false, data)
	if err != nil || len(res) != 1 {
		t.Fatalf("results=%d err=%v", len(res), err)
	}
	if string(res[0].Raw) != dummyKey || res[0].ExtraData["account"] != "examplestore" {
		t.Fatalf("unexpected result: raw=%q extra=%v", res[0].Raw, res[0].ExtraData)
	}
}

func TestFromData_NoAccountName(t *testing.T) {
	res, err := redactiontest.FromData(t, Scanner{}, context.Background(), false, []byte("AccountKey="+dummyKey))
	if err != nil || len(res) != 0 {
		t.Fatalf("results=%d err=%v", len(res), err)
	}
}
