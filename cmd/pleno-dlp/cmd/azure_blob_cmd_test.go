package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanAzureBlobEndToEnd(t *testing.T) {
	resetCommandFlags(t)
	awsKey := "AKIA" + "QYLPMN5HHHFPZAM2" // split so the pre-commit hook does not flag the fixture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sig") != "s3cr3t" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/ctr" && r.URL.Query().Get("comp") == "list":
			_, _ = w.Write([]byte(`<EnumerationResults><Blobs><Blob><Name>conf/app.env</Name><Properties><Etag>0x1</Etag><Content-Length>40</Content-Length></Properties></Blob></Blobs><NextMarker/></EnumerationResults>`))
		case r.URL.Path == "/ctr/conf/app.env":
			_, _ = w.Write([]byte("AWS_ACCESS_KEY_ID=" + awsKey + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("AZURE_STORAGE_SAS_TOKEN", "sp=rl&sig=s3cr3t")
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--no-verify", "--format", "json", "azure-blob", "--container-url", srv.URL + "/ctr"})
	if err := Root.Execute(); err == nil || !strings.Contains(err.Error(), "findings detected") {
		t.Fatalf("want findings-detected exit, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), `"blob": "conf/app.env"`) {
		t.Fatalf("missing blob metadata:\n%s", out.String())
	}
	if strings.Contains(out.String(), "s3cr3t") {
		t.Fatalf("output leaks SAS:\n%s", out.String())
	}
}
