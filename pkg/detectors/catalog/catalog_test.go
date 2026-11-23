package catalog

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
)

// Every imported pattern must compile under RE2 and carry a prefilter
// keyword: a keywordless format would never be scheduled by the engine.
func TestRulesCompileAndHaveKeywords(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range rules {
		if ids[r.ID] {
			t.Errorf("%s listed twice", r.ID)
		}
		ids[r.ID] = true
		if _, err := r.format().Compile(); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
		if len(r.Keywords) == 0 {
			t.Errorf("%s: no keywords", r.ID)
		}
		if r.Type.String() == "Unknown" {
			t.Errorf("%s: type has no String() name", r.ID)
		}
	}
}

func TestHostsRegisteredWithFormats(t *testing.T) {
	registered := map[detectors.DetectorType]bool{}
	for _, d := range detectors.All() {
		registered[d.Type()] = true
	}
	for _, h := range Hosts() {
		if !registered[h.Type()] {
			t.Errorf("host %s not registered", h.Type())
		}
		if len(h.Formats())+len(Extensions()[h.Type()]) == 0 || len(h.Keywords()) == 0 {
			t.Errorf("host %s has no formats or keywords", h.Type())
		}
	}
	for typ := range Extensions() {
		if len(detectors.FormatsFor(typ)) == 0 {
			t.Errorf("extension formats for %s not registered", typ)
		}
	}
}

// The secret group, entropy floor, and placeholder filter apply to host
// scanners and extensions alike; results are typed, tagged, and redacted.
func TestHostMatchContract(t *testing.T) {
	var h *Host
	for _, c := range Hosts() {
		if c.Type() == detectors.Typeform {
			h = c
		}
	}
	if h == nil {
		t.Fatal("Typeform host missing")
	}
	secret := "tfp_" + "Fq8XkL2mNp4Rs7Tv9Wy3Zb6Cd1Eh5G" + "j_Ka9Lm3Np7Qr2StUv4Wx6Yz8Ab1C"
	res, err := h.FromData(context.Background(), true, []byte("TYPEFORM_TOKEN="+secret+"\n"))
	if err != nil || len(res) != 1 {
		t.Fatalf("got %v, %v; want one result", res, err)
	}
	r := res[0]
	if string(r.Raw) != secret || r.DetectorType != detectors.Typeform || r.Verified {
		t.Fatalf("unexpected result %+v", r)
	}
	if r.ExtraData["verification"] != "not-attempted" || !strings.HasPrefix(r.ExtraData["format"], "betterleaks.typeform") {
		t.Fatalf("missing catalog tags: %v", r.ExtraData)
	}
	if strings.Contains(r.SafeRedacted(), secret) {
		t.Fatal("redacted form leaks the secret")
	}
	if res, _ := h.FromData(context.Background(), false, []byte("typeform tfp_${TYPEFORM_TOKEN}")); len(res) != 0 {
		t.Fatalf("placeholder matched: %v", res)
	}
}

// Every imported rule fires on its synthesized positive, through the
// redaction contract for hosts and through the engine's extension path
// for formats attached to existing provider types.
func TestEveryRuleHasAFiringFixture(t *testing.T) {
	hostByType := map[detectors.DetectorType]*Host{}
	for _, h := range Hosts() {
		hostByType[h.Type()] = h
	}
	for _, r := range rules {
		fx, ok := fixtures[r.ID]
		if !ok {
			t.Errorf("%s: no fixture", r.ID)
			continue
		}
		data := reverse(fx.data)
		var res []detectors.Result
		switch h := hostByType[r.Type]; {
		case r.Path != "":
			if got := detectors.MatchFormats(r.Type, []*detectors.Format{r.format()}, data, nil); len(got) != 0 {
				t.Errorf("%s: path-constrained format fired without a path", r.ID)
			}
			res = detectors.MatchFormatsAt(r.Type, []*detectors.Format{r.format()}, fx.path, data, nil)
		case h != nil:
			res, _ = redactiontest.FromData(t, h, context.Background(), false, data)
		default:
			res = detectors.MatchFormats(r.Type, []*detectors.Format{r.format()}, data, nil)
		}
		if len(res) == 0 {
			t.Errorf("%s: fixture %q did not fire", r.ID, data)
			continue
		}
		for _, x := range res {
			if x.DetectorType != r.Type || x.Verified {
				t.Errorf("%s: unexpected result type=%s verified=%v", r.ID, x.DetectorType, x.Verified)
			}
		}
	}
}

func reverse(s string) []byte {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}
