package htmlreport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestRenderEscapesAndOrders(t *testing.T) {
	low := *detectors.NewAccessMap("slack")
	low.Identity = detectors.AccessIdentity{ID: "U1", Type: "bot"}
	hi := *detectors.NewAccessMap("github")
	hi.Identity = detectors.AccessIdentity{ID: "1", Name: "<script>alert(1)</script>", Type: "user"}
	hi.Privileged = true
	hi.Resources = []detectors.AccessResource{{Type: "repository", Name: "acme/app", Permissions: []string{"admin"}}}
	hi.Activity = &detectors.AccessActivity{LastUsed: "2024-01-01T00:00:00Z"}
	var b bytes.Buffer
	if err := Render(&b, []Entry{{Map: low}, {Label: "GitHub gh...", Map: hi}}, "v1"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<script>alert") || !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("identity must be escaped")
	}
	if strings.Index(out, "github ·") > strings.Index(out, "slack ·") || !strings.Contains(out, "1 privileged") || !strings.Contains(out, "2024-01-01T00:00:00Z") {
		t.Fatal("privileged maps sort first with activity")
	}
}

func TestFromScan(t *testing.T) {
	am := detectors.NewAccessMap("gitlab")
	enc, _ := json.Marshal(am)
	rec := map[string]any{"detector": "GitLab", "redacted": "glp...", "extra_data": map[string]string{"blast_radius_map": string(enc)}, "source": map[string]any{"metadata": map[string]any{"file": "a.env"}}}
	line, _ := json.Marshal(rec)
	plain, _ := json.Marshal(map[string]any{"detector": "X"})
	for _, data := range [][]byte{append(append(line, '\n'), plain...), []byte("[" + string(line) + "," + string(plain) + "]")} {
		es, err := FromScan(data)
		if err != nil || len(es) != 1 || es[0].Label != "GitLab glp... — a.env" || es[0].Map.Provider != "gitlab" {
			t.Fatalf("%+v %v", es, err)
		}
	}
}
