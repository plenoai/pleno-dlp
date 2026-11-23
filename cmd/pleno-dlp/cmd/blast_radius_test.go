package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/blastradius"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/github"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

func withGitHubRegistry(t *testing.T) {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_live" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/user" {
			w.Header().Set("X-OAuth-Scopes", "repo")
			_, _ = w.Write([]byte(`{"login":"octo","id":1}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(s.Close)
	prev := blastRadiusRegistry
	blastRadiusRegistry = func() *blastradius.Registry {
		return blastradius.NewRegistry(blastradius.Provider{Name: "github", Mapper: github.Mapper{BaseURL: s.URL}, Detectors: []detectors.DetectorType{detectors.GitHub}})
	}
	t.Cleanup(func() { blastRadiusRegistry = prev })
}

func TestBlastRadiusCommand(t *testing.T) {
	withGitHubRegistry(t)
	c := &cobra.Command{}
	c.SetContext(context.Background())
	c.SetIn(strings.NewReader("ghp_live\n"))
	var out bytes.Buffer
	c.SetOut(&out)
	if err := runBlastRadius(c, []string{"GitHub"}); err != nil {
		t.Fatal(err)
	}
	var am detectors.AccessMap
	if err := json.Unmarshal(out.Bytes(), &am); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if am.Schema != detectors.AccessMapSchemaVersion || am.Identity.Name != "octo" || !am.Privileged {
		t.Fatalf("%+v", am)
	}
	if strings.Contains(out.String(), "ghp_live") {
		t.Fatal("output must not echo the credential")
	}
	if err := runBlastRadius(c, []string{"azure"}); err == nil || !strings.Contains(err.Error(), "supported: github") {
		t.Fatalf("err = %v", err)
	}
}

func TestBlastRadiusMapSink(t *testing.T) {
	withGitHubRegistry(t)
	sinkCap := &captureSink{}
	s := &blastRadiusMapSink{inner: sinkCap, reg: blastRadiusRegistry()}
	shared := map[string]string{"k": "v"}
	s.Emit(engine.Finding{Result: detectors.Result{DetectorType: detectors.GitHub, Raw: []byte("ghp_live"), Verified: true, ExtraData: shared}})
	s.Emit(engine.Finding{Result: detectors.Result{DetectorType: detectors.GitHub, Raw: []byte("ghp_live")}})
	s.Emit(engine.Finding{Result: detectors.Result{DetectorType: detectors.GitHub, Raw: []byte("ghp_dead"), Verified: true}})
	if len(sinkCap.findings) != 3 {
		t.Fatalf("got %d findings", len(sinkCap.findings))
	}
	got := sinkCap.findings[0].Result.ExtraData
	if got["blast_radius"] != "true" || !strings.Contains(got[blastradius.ExtraDataKey], `"name":"octo"`) || got["k"] != "v" {
		t.Fatalf("mapped extra %v", got)
	}
	if _, mutated := shared[blastradius.ExtraDataKey]; mutated {
		t.Fatal("sink must not mutate the detector's ExtraData map")
	}
	if _, ok := sinkCap.findings[1].Result.ExtraData[blastradius.ExtraDataKey]; ok {
		t.Fatal("unverified finding must not be mapped")
	}
	if e := sinkCap.findings[2].Result.ExtraData["blast_radius_error"]; !strings.Contains(e, "401") {
		t.Fatalf("error extra %q", e)
	}
}

func TestBlastRadiusHTMLAndReport(t *testing.T) {
	withGitHubRegistry(t)
	blastRadiusHTML = "-"
	t.Cleanup(func() { blastRadiusHTML = "" })
	c := &cobra.Command{}
	c.SetContext(context.Background())
	c.SetIn(strings.NewReader("ghp_live\n"))
	var out bytes.Buffer
	c.SetOut(&out)
	if err := runBlastRadius(c, []string{"github"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "<title>Access Map Report</title>") || !strings.Contains(out.String(), "octo") || strings.Contains(out.String(), "ghp_live") {
		t.Fatalf("html: %s", out.String())
	}

	am := detectors.NewAccessMap("github")
	am.Identity.Name = "octo"
	enc, _ := json.Marshal(am)
	line, _ := json.Marshal(map[string]any{"detector": "GitHub", "redacted": "ghp...", "extra_data": map[string]string{blastradius.ExtraDataKey: string(enc)}})
	p := t.TempDir() + "/scan.jsonl"
	if err := os.WriteFile(p, line, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	blastRadiusReportCmd.SetOut(&out)
	if err := blastRadiusReportCmd.RunE(blastRadiusReportCmd, []string{p}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "1 credential(s)") || !strings.Contains(out.String(), "GitHub ghp...") {
		t.Fatalf("report: %s", out.String())
	}
}
