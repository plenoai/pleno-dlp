package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestScanPostman(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/workspaces":
			json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{"id": "ws-1", "name": "My Workspace", "type": "personal"},
				},
			})
		case "/collections":
			json.NewEncoder(w).Encode(map[string]any{
				"collections": []map[string]any{
					{"uid": "col-uid-1", "name": "API Tests", "id": "col-1"},
				},
			})
		case "/collections/col-uid-1":
			json.NewEncoder(w).Encode(map[string]any{
				"collection": map[string]any{
					"info": map[string]any{"name": "API Tests"},
					"variable": []map[string]any{
						{"key": "api_key", "value": "sk-secret-value"},
					},
				},
			})
		case "/environments":
			json.NewEncoder(w).Encode(map[string]any{
				"environments": []map[string]any{
					{"uid": "env-uid-1", "name": "Production", "id": "env-1"},
				},
			})
		case "/environments/env-uid-1":
			json.NewEncoder(w).Encode(map[string]any{
				"environment": map[string]any{
					"name": "Production",
					"values": []map[string]any{
						{"key": "DB_PASSWORD", "value": "hunter2", "enabled": true},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	var chunks []string
	emit := func(data []byte, meta sources.Metadata) error {
		chunks = append(chunks, string(data))
		if meta.SIEM == nil || meta.SIEM.Provider != "postman" {
			t.Error("expected SIEM metadata with provider=postman")
		}
		return nil
	}

	err := scanPostman(context.Background(), Config{
		"api_key":  "test-api-key",
		"base_url": ts.URL,
	}, emit)
	if err != nil {
		t.Fatalf("scanPostman: %v", err)
	}
	// One chunk per collection, one per environment
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestScanPostman_MissingAPIKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	err := scanPostman(context.Background(), Config{"base_url": ts.URL}, nil)
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Errorf("expected api_key error, got: %v", err)
	}
}

func TestVerifyPostman(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" && r.Header.Get("X-Api-Key") == "valid-key" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ok, err := verifyPostman(context.Background(), Config{"base_url": ts.URL}, "valid-key")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
	ok, err = verifyPostman(context.Background(), Config{"base_url": ts.URL}, "bad-key")
	if err != nil || ok {
		t.Errorf("expected not verified, got ok=%v err=%v", ok, err)
	}
}

func TestPostmanConnectorRegistered(t *testing.T) {
	c, ok := Get("postman")
	if !ok {
		t.Fatal("postman connector not registered")
	}
	if c.Scan == nil {
		t.Error("postman connector has nil Scan")
	}
	if c.Verify == nil {
		t.Error("postman connector has nil Verify")
	}
	if c.Fingerprint == nil {
		t.Error("postman connector has nil Fingerprint")
	}
	if c.SourceType != sources.SourcePostman {
		t.Errorf("expected SourcePostman, got %v", c.SourceType)
	}
}

func TestPostmanSourceTypeString(t *testing.T) {
	if got := sources.SourcePostman.String(); got != "postman" {
		t.Errorf("SourcePostman.String()=%q, want %q", got, "postman")
	}
}
