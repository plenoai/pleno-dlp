//go:build detector_unit

package jetbrainswebservers

import (
	"context"
	"testing"
)

func TestFromData_FileTransferTag(t *testing.T) {
	data := []byte(`<webServer id="6ac7fc5c" name="root" url="https://example.com">
  <fileTransfer host="example.com" port="21" password="dff9dfdfdfdadfcfdfd8dff9dfcfdfcfdfc9dfd8dfcfdfdedffadfcbdfd9dfd9dfdddfc5dfd8dfcedf8b" username="root">
    <advancedOptions />
  </fileTransfer>
</webServer>`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	want := "dff9dfdfdfdadfcfdfd8dff9dfcfdfcfdfc9dfd8dfcfdfdedffadfcbdfd9dfd9dfdddfc5dfd8dfcedf8b"
	if string(res[0].Raw) != want {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["host"] != "example.com" || res[0].ExtraData["username"] != "root" {
		t.Fatalf("extra data = %+v", res[0].ExtraData)
	}
}

func TestFromData_AttributeOrderIndependent(t *testing.T) {
	// password listed before host — attribute order must not matter.
	data := []byte(`<fileTransfer password="R3alDeployPassZz8k" username="root" host="example.com" port="21">`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "R3alDeployPassZz8k" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"no fileTransfer tag", `<webServer password="R3alDeployPassZz8k" />`},
		{"placeholder password", `<fileTransfer host="x" password="password" username="root">`},
		{"too short", `<fileTransfer host="x" password="ab" username="root">`},
		{"missing password attribute", `<fileTransfer host="x" username="root">`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}
