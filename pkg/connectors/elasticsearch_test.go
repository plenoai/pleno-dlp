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

func TestScanElasticsearch(t *testing.T) {
	// scrollID returned on open, reused for drain pages.
	const scrollID = "test-scroll-id"
	page := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/_search") && !strings.Contains(r.URL.Path, "/scroll") && r.Method == http.MethodPost:
			// Initial scroll open
			json.NewEncoder(w).Encode(map[string]any{
				"_scroll_id": scrollID,
				"hits": map[string]any{
					"hits": []map[string]any{
						{"_index": "logs-2024", "_id": "1", "_source": map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "message": "api_key=sk-secret"}},
						{"_index": "logs-2024", "_id": "2", "_source": map[string]any{"@timestamp": "2024-01-01T00:01:00Z", "message": "normal log"}},
					},
				},
			})
		case r.URL.Path == "/_search/scroll" && r.Method == http.MethodPost:
			// Drain: first drain returns empty to signal end
			page++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"_scroll_id": scrollID,
				"hits":       map[string]any{"hits": []map[string]any{}},
			})
		case r.URL.Path == "/_search/scroll" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	var chunks []string
	emit := func(data []byte, meta sources.Metadata) error {
		chunks = append(chunks, string(data))
		if meta.SIEM == nil {
			t.Error("expected SIEM metadata")
		} else if meta.SIEM.Provider != "elasticsearch" {
			t.Errorf("expected provider=elasticsearch, got %s", meta.SIEM.Provider)
		}
		return nil
	}

	err := scanElasticsearch(context.Background(), Config{
		"host":    ts.URL,
		"api_key": "test-api-key",
	}, emit)
	if err != nil {
		t.Fatalf("scanElasticsearch: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestScanElasticsearch_MissingHost(t *testing.T) {
	err := scanElasticsearch(context.Background(), Config{}, nil)
	if err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("expected host error, got: %v", err)
	}
}

func TestVerifyElasticsearch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Header.Get("Authorization") == "ApiKey valid-key" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ok, err := verifyElasticsearch(context.Background(), Config{"host": ts.URL}, "valid-key")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
	ok, err = verifyElasticsearch(context.Background(), Config{"host": ts.URL}, "bad-key")
	if err != nil || ok {
		t.Errorf("expected not verified, got ok=%v err=%v", ok, err)
	}
}

func TestElasticsearchConnectorRegistered(t *testing.T) {
	c, ok := Get("elasticsearch")
	if !ok {
		t.Fatal("elasticsearch connector not registered")
	}
	if c.Scan == nil {
		t.Error("elasticsearch connector has nil Scan")
	}
	if c.Verify == nil {
		t.Error("elasticsearch connector has nil Verify")
	}
	if c.Fingerprint == nil {
		t.Error("elasticsearch connector has nil Fingerprint")
	}
	if c.SourceType != sources.SourceElasticsearch {
		t.Errorf("expected SourceElasticsearch, got %v", c.SourceType)
	}
}

func TestElasticsearchSourceTypeString(t *testing.T) {
	if got := sources.SourceElasticsearch.String(); got != "elasticsearch" {
		t.Errorf("SourceElasticsearch.String()=%q, want %q", got, "elasticsearch")
	}
}
