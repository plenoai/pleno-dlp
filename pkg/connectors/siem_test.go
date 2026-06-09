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

// --- Datadog ---

func TestScanDatadog(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/logs/events/search" {
			if r.Header.Get("DD-API-KEY") == "" || r.Header.Get("DD-APPLICATION-KEY") == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{
						"id": "evt-1",
						"attributes": map[string]any{
							"message":   "aws_secret_access_key=AKIAIOSFODNN7EXAMPLE",
							"timestamp": "2024-01-01T00:00:00Z",
							"tags":      "env:prod",
						},
					},
					{
						"id": "evt-2",
						"attributes": map[string]any{
							"message":   "nothing interesting here",
							"timestamp": "2024-01-01T00:01:00Z",
							"tags":      "env:staging",
						},
					},
				},
				"meta": map[string]any{
					"page": map[string]any{},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	var chunks []string
	emit := func(data []byte, meta sources.Metadata) error {
		chunks = append(chunks, string(data))
		if meta.SIEM == nil {
			t.Error("expected SIEM metadata")
		} else if meta.SIEM.Provider != "datadog" {
			t.Errorf("expected provider=datadog, got %s", meta.SIEM.Provider)
		}
		return nil
	}

	err := scanDatadog(context.Background(), Config{
		"api_key": "test-api-key",
		"app_key": "test-app-key",
		"site":    ts.URL,
	}, emit)
	if err != nil {
		t.Fatalf("scanDatadog: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestScanDatadog_MissingKeys(t *testing.T) {
	err := scanDatadog(context.Background(), Config{}, nil)
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Errorf("expected api_key error, got: %v", err)
	}
	err = scanDatadog(context.Background(), Config{"api_key": "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "app_key") {
		t.Errorf("expected app_key error, got: %v", err)
	}
}

func TestVerifyDatadog(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/validate" && r.Header.Get("DD-API-KEY") == "valid" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	ok, err := verifyDatadog(context.Background(), Config{"site": ts.URL}, "valid")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
	ok, err = verifyDatadog(context.Background(), Config{"site": ts.URL}, "invalid")
	if err != nil || ok {
		t.Errorf("expected not verified, got ok=%v err=%v", ok, err)
	}
}

// --- Splunk ---

func TestScanSplunk(t *testing.T) {
	var jobCreated bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/services/search/jobs" && r.Method == http.MethodPost:
			jobCreated = true
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"sid": "test-sid"})
		case strings.HasPrefix(r.URL.Path, "/services/search/jobs/test-sid") && !strings.Contains(r.URL.Path, "/results"):
			json.NewEncoder(w).Encode(map[string]any{
				"entry": []map[string]any{
					{"content": map[string]any{"isDone": true}},
				},
			})
		case strings.Contains(r.URL.Path, "/results"):
			json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]string{
					{"_raw": "password=hunter2", "_time": "2024-01-01T00:00:00Z", "_cd": "1:0"},
					{"_raw": "safe log entry", "_time": "2024-01-01T00:01:00Z", "_cd": "1:1"},
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
		if meta.SIEM == nil || meta.SIEM.Provider != "splunk" {
			t.Error("expected SIEM metadata with provider=splunk")
		}
		return nil
	}

	err := scanSplunk(context.Background(), Config{
		"token": "test-token",
		"host":  ts.URL,
	}, emit)
	if err != nil {
		t.Fatalf("scanSplunk: %v", err)
	}
	if !jobCreated {
		t.Error("expected search job to be created")
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestVerifySplunk(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/authentication/current-context" && r.Header.Get("Authorization") == "Bearer valid" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ok, err := verifySplunk(context.Background(), Config{"host": ts.URL}, "valid")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
	ok, err = verifySplunk(context.Background(), Config{"host": ts.URL}, "invalid")
	if err != nil || ok {
		t.Errorf("expected not verified, got ok=%v err=%v", ok, err)
	}
}

// --- BigQuery ---

func TestScanBigQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/bigquery/v2/projects/test-project/queries" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]any{
				"jobReference": map[string]string{"jobId": "job-123"},
				"schema": map[string]any{
					"fields": []map[string]string{{"name": "col1"}, {"name": "col2"}},
				},
				"rows": []map[string]any{
					{"f": []map[string]string{{"v": "secret_key=abc123"}, {"v": "data"}}},
					{"f": []map[string]string{{"v": "normal"}, {"v": "data2"}}},
				},
				"jobComplete": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	var chunks []string
	emit := func(data []byte, meta sources.Metadata) error {
		chunks = append(chunks, string(data))
		if meta.SIEM == nil || meta.SIEM.Provider != "bigquery" {
			t.Error("expected SIEM metadata with provider=bigquery")
		}
		return nil
	}

	err := scanBigQuery(context.Background(), Config{
		"token":    "test-token",
		"project":  "test-project",
		"query":    "SELECT * FROM dataset.table",
		"api_base": ts.URL,
	}, emit)
	if err != nil {
		t.Fatalf("scanBigQuery: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestVerifyBigQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer valid" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ok, err := verifyBigQuery(context.Background(), Config{"project": "p", "api_base": ts.URL}, "valid")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
}

// --- Redash ---

func TestScanRedash(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/queries" && r.URL.Query().Get("page") == "1":
			json.NewEncoder(w).Encode(map[string]any{
				"count": 1,
				"results": []map[string]any{
					{"id": 42, "name": "test query"},
				},
			})
		case r.URL.Path == "/api/queries/42" && r.Method == http.MethodGet:
			latestID := 100
			json.NewEncoder(w).Encode(map[string]any{
				"name":                 "test query",
				"latest_query_data_id": latestID,
			})
		case r.URL.Path == "/api/queries/42/results":
			json.NewEncoder(w).Encode(map[string]any{
				"query_result": map[string]any{
					"retrieved_at": "2024-01-01T00:00:00Z",
					"data": map[string]any{
						"columns": []map[string]string{{"name": "field1"}},
						"rows": []map[string]any{
							{"field1": "api_key=sk-12345"},
							{"field1": "normal data"},
						},
					},
				},
			})
		default:
			fmt.Fprintf(w, "{}")
		}
	}))
	defer ts.Close()

	var chunks []string
	emit := func(data []byte, meta sources.Metadata) error {
		chunks = append(chunks, string(data))
		if meta.SIEM == nil || meta.SIEM.Provider != "redash" {
			t.Error("expected SIEM metadata with provider=redash")
		}
		return nil
	}

	err := scanRedash(context.Background(), Config{
		"api_key": "test-key",
		"host":    ts.URL,
	}, emit)
	if err != nil {
		t.Fatalf("scanRedash: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
}

func TestVerifyRedash(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/session" && r.URL.Query().Get("api_key") == "valid" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ok, err := verifyRedash(context.Background(), Config{"host": ts.URL}, "valid")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
	ok, err = verifyRedash(context.Background(), Config{"host": ts.URL}, "invalid")
	if err != nil || ok {
		t.Errorf("expected not verified, got ok=%v err=%v", ok, err)
	}
}

// --- Registration ---

func TestSIEMConnectorsRegistered(t *testing.T) {
	for _, name := range []string{"datadog", "splunk", "bigquery", "redash"} {
		c, ok := Get(name)
		if !ok {
			t.Errorf("connector %q not registered", name)
			continue
		}
		if c.Scan == nil {
			t.Errorf("connector %q has nil Scan", name)
		}
		if c.Verify == nil {
			t.Errorf("connector %q has nil Verify", name)
		}
		if c.Fingerprint == nil {
			t.Errorf("connector %q has nil Fingerprint", name)
		}
	}
}

func TestSIEMIncrementalStateSkipsUnchangedEvents(t *testing.T) {
	data := []byte("token=unchanged")
	key := "event-1"
	state := &siemScanState{
		previous: &siemIncrementalState{
			Version: 1,
			Events: map[string]siemEventIncrementalState{
				key: siemEventState(data, "2026-06-09T00:00:00Z"),
			},
		},
		next: &siemIncrementalState{Version: 1, Events: map[string]siemEventIncrementalState{}},
	}
	var emitted int
	err := emitSIEMIncremental(key, data, "2026-06-09T00:00:00Z", state, sources.Metadata{}, func([]byte, sources.Metadata) error {
		emitted++
		return nil
	})
	if err != nil {
		t.Fatalf("emitSIEMIncremental unchanged: %v", err)
	}
	if emitted != 0 {
		t.Fatalf("unchanged event emitted %d times, want 0", emitted)
	}
	if _, ok := state.next.Events[key]; !ok {
		t.Fatal("next state did not retain skipped event")
	}

	err = emitSIEMIncremental(key, []byte("token=changed"), "2026-06-09T00:00:00Z", state, sources.Metadata{}, func([]byte, sources.Metadata) error {
		emitted++
		return nil
	})
	if err != nil {
		t.Fatalf("emitSIEMIncremental changed: %v", err)
	}
	if emitted != 1 {
		t.Fatalf("changed event emitted %d times, want 1", emitted)
	}
}

func TestSIEMSourceTypes(t *testing.T) {
	cases := []struct {
		name string
		want sources.SourceType
	}{
		{"datadog", sources.SourceDatadog},
		{"splunk", sources.SourceSplunk},
		{"bigquery", sources.SourceBigQuery},
		{"redash", sources.SourceRedash},
	}
	for _, tc := range cases {
		c, _ := Get(tc.name)
		if c.SourceType != tc.want {
			t.Errorf("%s: SourceType=%d, want %d", tc.name, c.SourceType, tc.want)
		}
	}
}

func TestSIEMSourceTypeStrings(t *testing.T) {
	cases := []struct {
		st   sources.SourceType
		want string
	}{
		{sources.SourceDatadog, "datadog"},
		{sources.SourceSplunk, "splunk"},
		{sources.SourceBigQuery, "bigquery"},
		{sources.SourceRedash, "redash"},
	}
	for _, tc := range cases {
		if got := tc.st.String(); got != tc.want {
			t.Errorf("SourceType(%d).String()=%q, want %q", tc.st, got, tc.want)
		}
	}
}
