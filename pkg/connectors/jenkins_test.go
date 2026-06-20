package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestScanJenkins(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/json":
			json.NewEncoder(w).Encode(map[string]any{
				"jobs": []map[string]any{
					{"name": "my-job", "url": r.Host + "/job/my-job/", "_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob"},
				},
			})
		case r.URL.Path == "/job/my-job/config.xml":
			fmt.Fprintln(w, `<project><properties><hudson.model.PasswordParameterDefinition><name>SECRET</name><defaultValue>hunter2</defaultValue></hudson.model.PasswordParameterDefinition></properties></project>`)
		case r.URL.Path == "/job/my-job/api/json":
			json.NewEncoder(w).Encode(map[string]any{
				"builds": []map[string]any{
					{"number": 1, "url": "/job/my-job/1/"},
				},
			})
		case r.URL.Path == "/job/my-job/1/consoleText":
			fmt.Fprintln(w, "build started\nPASSWORD=secret123\nbuild done")
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	var chunks []string
	emit := func(data []byte, meta sources.Metadata) error {
		chunks = append(chunks, string(data))
		if meta.SIEM == nil || meta.SIEM.Provider != "jenkins" {
			t.Error("expected SIEM metadata with provider=jenkins")
		}
		return nil
	}

	err := scanJenkins(context.Background(), Config{
		"host":  ts.URL,
		"user":  "admin",
		"token": "test-token",
	}, emit)
	if err != nil {
		t.Fatalf("scanJenkins: %v", err)
	}
	// Expect config.xml chunk + console log chunk
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d: %v", len(chunks), chunks)
	}
}

func TestScanJenkins_MissingCredentials(t *testing.T) {
	err := scanJenkins(context.Background(), Config{}, nil)
	if err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("expected host error, got: %v", err)
	}
	err = scanJenkins(context.Background(), Config{"host": "http://x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "user") {
		t.Errorf("expected user error, got: %v", err)
	}
	err = scanJenkins(context.Background(), Config{"host": "http://x", "user": "u"}, nil)
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("expected token error, got: %v", err)
	}
}

func TestVerifyJenkins(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "admin" && pass == "valid-token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ok, err := verifyJenkins(context.Background(), Config{"host": ts.URL, "user": "admin"}, "valid-token")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
	ok, err = verifyJenkins(context.Background(), Config{"host": ts.URL, "user": "admin"}, "bad-token")
	if err != nil || ok {
		t.Errorf("expected not verified, got ok=%v err=%v", ok, err)
	}
}

func TestJenkinsConnectorRegistered(t *testing.T) {
	c, ok := Get("jenkins")
	if !ok {
		t.Fatal("jenkins connector not registered")
	}
	if c.Scan == nil {
		t.Error("jenkins connector has nil Scan")
	}
	if c.Verify == nil {
		t.Error("jenkins connector has nil Verify")
	}
	if c.Fingerprint == nil {
		t.Error("jenkins connector has nil Fingerprint")
	}
	if c.SourceType != sources.SourceJenkins {
		t.Errorf("expected SourceJenkins, got %v", c.SourceType)
	}
}

func TestJenkinsSourceTypeString(t *testing.T) {
	if got := sources.SourceJenkins.String(); got != "jenkins" {
		t.Errorf("SourceJenkins.String()=%q, want %q", got, "jenkins")
	}
}
