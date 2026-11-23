package detectors

import (
	"context"
	"testing"
)

const fmtTestType = DetectorType(1<<29 + 1)

type fmtTestDetector struct{}

func (fmtTestDetector) Type() DetectorType { return fmtTestType }
func (fmtTestDetector) Keywords() []string { return []string{"Native", "shared"} }
func (fmtTestDetector) FromData(context.Context, bool, []byte) ([]Result, error) {
	return nil, nil
}

func TestMatchFormatsGates(t *testing.T) {
	f := &Format{ID: "t.group", Keywords: []string{"key"}, Pattern: `key=([A-Za-z0-9$_{}]+);(\w+)`, Group: 2, MinEntropy: 2.5}
	cases := []struct {
		in   string
		want []string
	}{
		{"key=aaa;Zq8Lm3Xc", []string{"Zq8Lm3Xc"}},              // explicit group 2
		{"key=aaa;aaaaaaaa", nil},                               // entropy floor
		{"KEY=aaa;Zq8Lm3Xc", nil},                               // case-sensitive pattern
		{"nothing here", nil},                                   // keyword gate
		{"key=a;Zq8Lm3Xc key=b;Zq8Lm3Xc", []string{"Zq8Lm3Xc"}}, // dedup
	}
	for _, c := range cases {
		got := MatchFormats(fmtTestType, []*Format{f}, []byte(c.in), nil)
		if len(got) != len(c.want) {
			t.Fatalf("%q: got %d results, want %d", c.in, len(got), len(c.want))
		}
		for i, r := range got {
			if string(r.Raw) != c.want[i] || r.Verified || r.ExtraData["format"] != "t.group" {
				t.Fatalf("%q: unexpected %+v", c.in, r)
			}
			if r.SafeRedacted() == string(r.Raw) {
				t.Fatalf("%q: redacted form equals the secret", c.in)
			}
		}
	}
	first := &Format{ID: "t.first", Pattern: `(?:a=(\w+)|b=(\w+))`}
	if got := MatchFormats(fmtTestType, []*Format{first}, []byte("b=Zq8Lm3Xc"), nil); len(got) != 1 || string(got[0].Raw) != "Zq8Lm3Xc" {
		t.Fatalf("first participating group: %+v", got)
	}
	for _, ph := range []string{"${API_TOKEN}", "$api_token", "{{.Values.token}}", "null", "xxxxxxxx"} {
		if got := MatchFormats(fmtTestType, []*Format{{ID: "t.ph", Pattern: `tok=(\S+)`}}, []byte("tok="+ph), nil); len(got) != 0 {
			t.Fatalf("placeholder %q matched", ph)
		}
	}
	if got := MatchFormats(fmtTestType, []*Format{{ID: "t.ph2", Pattern: `tok=(\S+)`}}, []byte("tok=$aact_prod_Zq8Lm3Xc"), nil); len(got) != 1 {
		t.Fatal("a $-prefixed token with digits is not a template variable")
	}
	existing := []Result{{DetectorType: fmtTestType, Raw: []byte("Zq8Lm3Xc")}}
	if got := MatchFormats(fmtTestType, []*Format{first}, []byte("a=Zq8Lm3Xc"), existing); len(got) != 1 {
		t.Fatalf("format duplicated a native result: %+v", got)
	}
}

func TestMatchFormatsPathConstraint(t *testing.T) {
	f := &Format{ID: "t.path", Pattern: `pw=(\w+)`, Path: `(?i)\.tf$`}
	data := []byte("pw=Zq8Lm3Xc")
	if got := MatchFormats(fmtTestType, []*Format{f}, data, nil); len(got) != 0 {
		t.Fatal("path-constrained format fired without a path")
	}
	if got := MatchFormatsAt(fmtTestType, []*Format{f}, "infra/main.go", data, nil); len(got) != 0 {
		t.Fatal("path-constrained format fired on a non-matching path")
	}
	if got := MatchFormatsAt(fmtTestType, []*Format{f}, "infra/MAIN.TF", data, nil); len(got) != 1 {
		t.Fatal("path-constrained format did not fire on a matching path")
	}
}

func TestKeywordsWithFormats(t *testing.T) {
	RegisterFormats(fmtTestType, &Format{ID: "t.kw", Keywords: []string{"SHARED", "extra"}, Pattern: `x`})
	got := KeywordsWithFormats(fmtTestDetector{})
	want := []string{"Native", "shared", "extra"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate format id did not panic")
		}
	}()
	RegisterFormats(fmtTestType, &Format{ID: "t.kw", Pattern: `y`})
}
