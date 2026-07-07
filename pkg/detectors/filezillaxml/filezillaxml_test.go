//go:build detector_unit

package filezillaxml

import (
	"context"
	"testing"
)

func TestFromData_Base64Encoded(t *testing.T) {
	// base64("real-master-pw-hash-Zz8k9f")
	data := []byte(`<Server>
	<Host>localhost</Host>
	<User>root</User>
	<Pass encoding="base64">cmVhbC1tYXN0ZXItcHctaGFzaC1aejhrOWY=</Pass>
</Server>`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "real-master-pw-hash-Zz8k9f" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["encoding"] != "base64" {
		t.Fatalf("encoding = %q", res[0].ExtraData["encoding"])
	}
}

func TestFromData_PlaintextPass(t *testing.T) {
	data := []byte(`<Server>
	<Host>example.com</Host>
	<User>root</User>
	<Pass>ExamplePas123</Pass>
</Server>`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "ExamplePas123" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["encoding"] != "" {
		t.Fatalf("expected no encoding, got %q", res[0].ExtraData["encoding"])
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"empty tag", `<Pass></Pass>`},
		{"placeholder plaintext", `<Pass>password</Pass>`},
		{"too short", `<Pass>ab</Pass>`},
		{"invalid base64", `<Pass encoding="base64">not-valid-base64!!</Pass>`},
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

func TestFromData_Dedup(t *testing.T) {
	data := []byte(`<Pass encoding="base64">cmVhbC1tYXN0ZXItcHctaGFzaC1aejhrOWY=</Pass>` +
		`<Pass encoding="base64">cmVhbC1tYXN0ZXItcHctaGFzaC1aejhrOWY=</Pass>`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1 deduped, got %d", len(res))
	}
}
